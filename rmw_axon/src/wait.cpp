#include "rmw_axon/internal.hpp"
#include <cerrno>
#include <sys/epoll.h>
#include <unordered_set>

#define MAX_FDS 1024

rmw_wait_set_t *rmw_create_wait_set(rmw_context_t *context,
                                    size_t max_conditions) {
  (void)max_conditions;
  uint64_t sid = get_session_id(context);
  if (sid == 0) {
    RMW_SET_ERROR_MSG("invalid session id in context");
    return NULL;
  }

  int64_t ws_handle = axon_session_create_waitset(sid);
  if (ws_handle < 0) {
    RMW_SET_ERROR_MSG("axon_session_create_waitset failed");
    return NULL;
  }

  axon_waitset_data_t *ws_data =
      (axon_waitset_data_t *)rmw_allocate(sizeof(axon_waitset_data_t));
  if (!ws_data) {
    axon_session_destroy_waitset(sid, (uint64_t)ws_handle);
    RMW_SET_ERROR_MSG("failed to allocate waitset data");
    return NULL;
  }
  ws_data->session_id = sid;
  ws_data->ws_handle = ws_handle;

  rmw_wait_set_t *wait_set = rmw_wait_set_allocate();
  if (!wait_set) {
    axon_session_destroy_waitset(sid, (uint64_t)ws_handle);
    rmw_free(ws_data);
    RMW_SET_ERROR_MSG("failed to allocate wait set");
    return NULL;
  }
  wait_set->implementation_identifier = "rmw_axon";
  wait_set->data = ws_data;
  return wait_set;
}

rmw_ret_t rmw_destroy_wait_set(rmw_wait_set_t *wait_set) {
  if (wait_set) {
    if (wait_set->data) {
      axon_waitset_data_t *ws_data = (axon_waitset_data_t *)wait_set->data;
      axon_session_destroy_waitset(ws_data->session_id,
                                   (uint64_t)ws_data->ws_handle);
      rmw_free(ws_data);
    }
    rmw_wait_set_free(wait_set);
  }
  return RMW_RET_OK;
}

static bool is_fd_ready(int fd, struct epoll_event *events, int nfds) {
  for (int i = 0; i < nfds; ++i) {
    if ((events[i].events & EPOLLIN) && events[i].data.fd == fd)
      return true;
  }
  return false;
}

static bool add_epoll_fd_once(int epfd, int fd, struct epoll_event *ev,
                              int *registered_fds,
                              size_t *registered_fd_count, int *nfds) {
  if (fd < 0 || *nfds >= MAX_FDS) {
    return false;
  }
  for (size_t i = 0; i < *registered_fd_count; ++i) {
    if (registered_fds[i] == fd) {
      return true;
    }
  }
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev) < 0 && errno != EEXIST) {
    return false;
  }
  registered_fds[*registered_fd_count] = fd;
  ++(*registered_fd_count);
  ++(*nfds);
  return true;
}

static int axon_wait_poll_cap_ms(bool has_services_or_clients) {
  const char *env = getenv("AXON_WAIT_POLL_MS");
  if (env && env[0] != '\0') {
    char *end = nullptr;
    long parsed = strtol(env, &end, 10);
    if (end != env && parsed >= 0 && parsed <= 1000) {
      return static_cast<int>(parsed);
    }
  }
  return has_services_or_clients ? 10 : 100;
}

rmw_ret_t rmw_wait(rmw_subscriptions_t *subscriptions,
                   rmw_guard_conditions_t *guard_conditions,
                   rmw_services_t *services, rmw_clients_t *clients,
                   rmw_events_t *events, rmw_wait_set_t *wait_set,
                   const rmw_time_t *wait_timeout) {
  if (events) {
    for (size_t i = 0; i < events->event_count; ++i) {
      events->events[i] = nullptr;
    }
  }
  uint64_t wait_session_id = 0;
  if (wait_set && wait_set->data) {
    axon_waitset_data_t *ws_data =
        static_cast<axon_waitset_data_t *>(wait_set->data);
    wait_session_id = ws_data->session_id;
    (void)axon_session_sync_routes(wait_session_id);
  }

  int epfd = epoll_create1(0);
  if (epfd < 0) return RMW_RET_ERROR;

  struct epoll_event ev;
  struct epoll_event events_buf[MAX_FDS];
  int registered_fds[MAX_FDS];
  size_t registered_fd_count = 0;
  int nfds = 0;

  size_t sub_count = subscriptions ? subscriptions->subscriber_count : 0;
  size_t gc_count =
      guard_conditions ? guard_conditions->guard_condition_count : 0;
  size_t svc_count = services ? services->service_count : 0;
  size_t cli_count = clients ? clients->client_count : 0;

  bool subs_ready = false;
  bool svcs_ready = false;
  bool clis_ready = false;

  // Process all entity types: detect ready data, add eventfds to epoll
  for (size_t i = 0; i < sub_count && nfds < MAX_FDS; ++i) {
    if (subscriptions->subscribers[i]) {
      axon_subscription_data_t *ax_data =
          static_cast<axon_subscription_data_t *>(
              subscriptions->subscribers[i]);
      if (ax_data && ax_data->eventfd >= 0) {
        int avail = axon_session_data_available(
            ax_data->session_id, ax_data->topic_name, ax_data->next_seq);
        if (avail > 0) {
          subs_ready = true;
        }
        ev.events = EPOLLIN;
        ev.data.fd = ax_data->eventfd;
        add_epoll_fd_once(epfd, ax_data->eventfd, &ev, registered_fds,
                          &registered_fd_count, &nfds);
      }
    }
  }

  for (size_t i = 0; i < gc_count && nfds < MAX_FDS; ++i) {
    if (guard_conditions->guard_conditions[i]) {
      axon_guard_condition_data_t *gc_data =
          static_cast<axon_guard_condition_data_t *>(
              guard_conditions->guard_conditions[i]);
      if (gc_data && gc_data->event_fd >= 0) {
        ev.events = EPOLLIN;
        ev.data.fd = gc_data->event_fd;
        add_epoll_fd_once(epfd, gc_data->event_fd, &ev, registered_fds,
                          &registered_fd_count, &nfds);
      }
    }
  }

  for (size_t i = 0; i < svc_count && nfds < MAX_FDS; ++i) {
    if (services->services[i]) {
      axon_service_data_t *ax_data =
          static_cast<axon_service_data_t *>(services->services[i]);
      if (ax_data && ax_data->request_eventfd >= 0) {
        int avail = axon_session_service_request_data_available(
            ax_data->session_id, ax_data->service_name, ax_data->next_seq);
        if (avail > 0) {
          svcs_ready = true;
        }
        ev.events = EPOLLIN;
        ev.data.fd = ax_data->request_eventfd;
        add_epoll_fd_once(epfd, ax_data->request_eventfd, &ev, registered_fds,
                          &registered_fd_count, &nfds);
      }
    }
  }

  for (size_t i = 0; i < cli_count && nfds < MAX_FDS; ++i) {
    if (clients->clients[i]) {
      axon_client_data_t *ax_data =
          static_cast<axon_client_data_t *>(clients->clients[i]);
      if (ax_data && ax_data->response_eventfd >= 0) {
        int avail = axon_session_service_response_data_available(
            ax_data->session_id, ax_data->service_name, ax_data->next_seq);
        if (avail > 0) {
          clis_ready = true;
        }
        ev.events = EPOLLIN;
        ev.data.fd = ax_data->response_eventfd;
        add_epoll_fd_once(epfd, ax_data->response_eventfd, &ev, registered_fds,
                          &registered_fd_count, &nfds);
      }
    }
  }

  if (nfds == 0) {
    close(epfd);
    for (size_t i = 0; i < sub_count; ++i) {
      if (subscriptions->subscribers[i]) {
        axon_subscription_data_t *ax_data =
            static_cast<axon_subscription_data_t *>(
                subscriptions->subscribers[i]);
        int avail = axon_session_data_available(
            ax_data->session_id, ax_data->topic_name, ax_data->next_seq);
        if (avail <= 0)
          subscriptions->subscribers[i] = NULL;
      }
    }
    for (size_t i = 0; i < svc_count; ++i) {
      if (services->services[i]) {
        axon_service_data_t *ax_data =
            static_cast<axon_service_data_t *>(services->services[i]);
        int avail = axon_session_service_request_data_available(
            ax_data->session_id, ax_data->service_name, ax_data->next_seq);
        if (avail <= 0)
          services->services[i] = NULL;
      }
    }
    for (size_t i = 0; i < cli_count; ++i) {
      if (clients->clients[i]) {
        axon_client_data_t *ax_data =
            static_cast<axon_client_data_t *>(clients->clients[i]);
        int avail = axon_session_service_response_data_available(
            ax_data->session_id, ax_data->service_name, ax_data->next_seq);
        if (avail <= 0)
          clients->clients[i] = NULL;
      }
    }
    return RMW_RET_OK;
  }

  // Cap polling to ensure periodic data_available checks catch
  // responses even when cross-process eventfd signaling has silently failed
  // (SCM_RIGHTS receive failure). Service/client waits use a lower default
  // cap than topic-only waits: lifecycle managers often have short service
  // timeouts, and adding 100ms per request/response hop is enough to cause
  // false bringup failures under Gazebo/Nav2 load.
  // We do NOT return RMW_RET_TIMEOUT for INFINITE waits (wait_timeout == NULL)
  // — that would crash rcl_wait's graph listener which calls rmw_wait(INFINITE)
  // and treats any timeout as fatal.
  int poll_cap_ms = axon_wait_poll_cap_ms(svc_count > 0 || cli_count > 0);

  // Track whether we should skip epoll_wait because some data is already ready
  bool data_already_ready = subs_ready || svcs_ready || clis_ready;

  // Non-destructive SHM readiness probe used between poll slices.
  auto any_shm_data_ready = [&]() -> bool {
    for (size_t i = 0; i < sub_count; ++i) {
      if (subscriptions->subscribers[i]) {
        axon_subscription_data_t *ax_data =
            static_cast<axon_subscription_data_t *>(
                subscriptions->subscribers[i]);
        if (ax_data && axon_session_data_available(ax_data->session_id,
                                                   ax_data->topic_name,
                                                   ax_data->next_seq) > 0)
          return true;
      }
    }
    for (size_t i = 0; i < svc_count; ++i) {
      if (services->services[i]) {
        axon_service_data_t *ax_data =
            static_cast<axon_service_data_t *>(services->services[i]);
        if (ax_data && axon_session_service_request_data_available(
                           ax_data->session_id, ax_data->service_name,
                           ax_data->next_seq) > 0)
          return true;
      }
    }
    for (size_t i = 0; i < cli_count; ++i) {
      if (clients->clients[i]) {
        axon_client_data_t *ax_data =
            static_cast<axon_client_data_t *>(clients->clients[i]);
        if (ax_data && axon_session_service_response_data_available(
                           ax_data->session_id, ax_data->service_name,
                           ax_data->next_seq) > 0)
          return true;
      }
    }
    return false;
  };

  // Honor the caller's full timeout instead of returning RMW_RET_TIMEOUT
  // after a single capped slice: wait in poll_cap_ms slices, probing SHM
  // readiness between slices (cross-process eventfd wakeups can silently
  // fail, see comment above). Finite waits loop until the user deadline;
  // INFINITE waits keep polling until an entity is actually ready. Returning
  // OK with an all-null wait set causes spurious executor wakeups and violates
  // the blocking semantics expected by rcl and rclcpp.
  int64_t remaining_ms = -1;
  if (wait_timeout) {
    int64_t user_ms =
        wait_timeout->sec * 1000LL + (int64_t)(wait_timeout->nsec / 1000000LL);
    remaining_ms = user_ms < 0 ? 0 : user_ms;
  }

  int ret = 0;
  while (!data_already_ready) {
    int slice_ms = poll_cap_ms;
    if (remaining_ms >= 0 && remaining_ms < (int64_t)slice_ms)
      slice_ms = (int)remaining_ms;
    ret = epoll_wait(epfd, events_buf, MAX_FDS, slice_ms);
    // Signals can interrupt epoll_wait without invalidating the wait set.
    // Retrying the same slice preserves the caller's timeout semantics; mapping
    // EINTR to RMW_RET_TIMEOUT is incorrect for infinite waits and makes
    // rclcpp's GraphListener throw "rcl_wait unexpectedly timed out", which
    // terminates otherwise healthy ROS nodes.
    if (ret < 0 && errno == EINTR) {
      continue;
    }
    if (ret != 0)
      break; // fds ready, or error handled below
    if (wait_session_id != 0)
      (void)axon_session_sync_routes(wait_session_id);
    if (any_shm_data_ready()) {
      data_already_ready = true;
      break;
    }
    if (remaining_ms < 0)
      continue; // infinite wait: keep probing until data or an fd is ready
    remaining_ms -= slice_ms;
    if (remaining_ms <= 0)
      break; // user timeout elapsed
  }
  close(epfd);

  if (!data_already_ready && ret < 0) {
    return RMW_RET_ERROR;
  }

  // Several subscriptions can share the same topic eventfd (fan-out).  The
  // eventfd is only a wake-up hint, not proof that every subscription has a
  // sample at its own cursor.  Drain one token per descriptor and always
  // re-check the per-subscription sequence before marking it ready.
  std::unordered_set<int> drained_fds;
  auto drain_ready_fd_once = [&drained_fds](int fd) {
    if (fd < 0 || !drained_fds.insert(fd).second) {
      return;
    }
    uint64_t val;
    ssize_t _r = read(fd, &val, sizeof(val));
    (void)_r;
  };

  for (size_t i = 0; i < sub_count; ++i) {
    if (subscriptions->subscribers[i]) {
      axon_subscription_data_t *ax_data =
          static_cast<axon_subscription_data_t *>(
              subscriptions->subscribers[i]);
      if (!ax_data) {
        subscriptions->subscribers[i] = NULL;
        continue;
      }
      if (is_fd_ready(ax_data->eventfd, events_buf, ret)) {
        drain_ready_fd_once(ax_data->eventfd);
      }
      int avail = axon_session_data_available(
          ax_data->session_id, ax_data->topic_name, ax_data->next_seq);
      if (avail <= 0) {
        subscriptions->subscribers[i] = NULL;
      }
    }
  }

  for (size_t i = 0; i < gc_count; ++i) {
    if (guard_conditions->guard_conditions[i]) {
      bool ready = false;
      axon_guard_condition_data_t *gc_data =
          static_cast<axon_guard_condition_data_t *>(
              guard_conditions->guard_conditions[i]);
      if (gc_data &&
          gc_data->triggered.exchange(false, std::memory_order_acq_rel)) {
        ready = true;
        uint64_t val;
        ssize_t _r = read(gc_data->event_fd, &val, sizeof(val));
        (void)_r;
      } else if (gc_data && gc_data->owns_event_fd &&
                 is_fd_ready(gc_data->event_fd, events_buf, ret)) {
        ready = true;
        uint64_t val;
        ssize_t _r = read(gc_data->event_fd, &val, sizeof(val));
        (void)_r;
      }
      if (!ready)
        guard_conditions->guard_conditions[i] = NULL;
    }
  }

  for (size_t i = 0; i < svc_count; ++i) {
    if (services->services[i]) {
      axon_service_data_t *ax_data =
          static_cast<axon_service_data_t *>(services->services[i]);
      if (!ax_data) {
        services->services[i] = NULL;
        continue;
      }
      if (is_fd_ready(ax_data->request_eventfd, events_buf, ret)) {
        drain_ready_fd_once(ax_data->request_eventfd);
      }
      int avail = axon_session_service_request_data_available(
          ax_data->session_id, ax_data->service_name, ax_data->next_seq);
      if (avail <= 0) {
        services->services[i] = NULL;
      }
    }
  }

  for (size_t i = 0; i < cli_count; ++i) {
    if (clients->clients[i]) {
      axon_client_data_t *ax_data =
          static_cast<axon_client_data_t *>(clients->clients[i]);
      if (!ax_data) {
        clients->clients[i] = NULL;
        continue;
      }
      if (is_fd_ready(ax_data->response_eventfd, events_buf, ret)) {
        drain_ready_fd_once(ax_data->response_eventfd);
      }
      int avail = axon_session_service_response_data_available(
          ax_data->session_id, ax_data->service_name, ax_data->next_seq);
      if (avail <= 0) {
        clients->clients[i] = NULL;
      }
    }
  }

  // When epoll_wait timed out (ret == 0) and no entity is ready after the
  // data_available() fallback, the finite user timeout has elapsed. Infinite
  // waits cannot reach this point without a ready entity because the loop
  // above keeps polling.
  if (!data_already_ready && ret == 0) {
    bool any_ready = false;
    if (subscriptions) {
      for (size_t i = 0; i < sub_count; ++i)
        if (subscriptions->subscribers[i]) { any_ready = true; break; }
    }
    if (!any_ready && services) {
      for (size_t i = 0; i < svc_count; ++i)
        if (services->services[i]) { any_ready = true; break; }
    }
    if (!any_ready && clients) {
      for (size_t i = 0; i < cli_count; ++i)
        if (clients->clients[i]) { any_ready = true; break; }
    }
    if (!any_ready) {
      if (wait_timeout)
        return RMW_RET_TIMEOUT;
      return RMW_RET_OK;
    }
  }

  return RMW_RET_OK;
}
