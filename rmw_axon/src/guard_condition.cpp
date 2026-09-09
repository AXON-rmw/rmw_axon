#include "rmw_axon/internal.hpp"

#include <cerrno>
#include <new>

rmw_guard_condition_t *rmw_create_guard_condition(rmw_context_t *context) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(context, NULL);

  rmw_guard_condition_t *gc = rmw_guard_condition_allocate();
  if (!gc) {
    RMW_SET_ERROR_MSG("failed to allocate guard condition");
    return NULL;
  }

  axon_guard_condition_data_t *data =
      (axon_guard_condition_data_t *)rmw_allocate(
          sizeof(axon_guard_condition_data_t));
  if (!data) {
    rmw_guard_condition_free(gc);
    RMW_SET_ERROR_MSG("failed to allocate guard condition data");
    return NULL;
  }

  data->event_fd = -1;
  data->owns_event_fd = true;
  new (&data->triggered) std::atomic_bool(false);

  data->event_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (data->event_fd < 0) {
    const int saved_errno = errno;
    rmw_free(data);
    rmw_guard_condition_free(gc);
    RMW_SET_ERROR_MSG_WITH_FORMAT_STRING(
        "eventfd creation failed: %s (errno %d)", strerror(saved_errno),
        saved_errno);
    return NULL;
  }

  gc->implementation_identifier = "rmw_axon";
  gc->data = data;
  gc->context = context;
  axon_trace_fd_event("create", "guard_condition", data->event_fd, nullptr);
  return gc;
}

bool axon_guard_condition_use_dedicated_eventfd(
    rmw_guard_condition_t *guard_condition) {
  if (!guard_condition || !guard_condition->data) {
    return false;
  }
  axon_guard_condition_data_t *data =
      (axon_guard_condition_data_t *)guard_condition->data;
  if (data->owns_event_fd) {
    return true;
  }

  int fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (fd < 0) {
    const int saved_errno = errno;
    RMW_SET_ERROR_MSG_WITH_FORMAT_STRING(
        "dedicated guard eventfd creation failed: %s (errno %d)",
        strerror(saved_errno), saved_errno);
    return false;
  }
  data->event_fd = fd;
  data->owns_event_fd = true;
  data->triggered.store(false, std::memory_order_release);
  axon_trace_fd_event("create", "guard_condition_dedicated", data->event_fd,
                      nullptr);
  return true;
}

rmw_ret_t rmw_destroy_guard_condition(rmw_guard_condition_t *guard_condition) {
  if (guard_condition) {
    if (guard_condition->data) {
      axon_guard_condition_data_t *data =
          (axon_guard_condition_data_t *)guard_condition->data;
      if (data->owns_event_fd && data->event_fd >= 0) {
        axon_trace_fd_event("destroy", "guard_condition", data->event_fd,
                            nullptr);
        close(data->event_fd);
      }
      rmw_free(data);
    }
    rmw_guard_condition_free(guard_condition);
  }
  return RMW_RET_OK;
}

rmw_ret_t
rmw_trigger_guard_condition(const rmw_guard_condition_t *guard_condition) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(guard_condition, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(guard_condition->data,
                                  RMW_RET_INVALID_ARGUMENT);

  axon_guard_condition_data_t *data =
      (axon_guard_condition_data_t *)guard_condition->data;
  data->triggered.store(true, std::memory_order_release);
  uint64_t val = 1;
  ssize_t ret = write(data->event_fd, &val, sizeof(val));
  if (ret != (ssize_t)sizeof(val)) {
    const int saved_errno = errno;
    if (saved_errno == EAGAIN) {
      return RMW_RET_OK;
    }
    RMW_SET_ERROR_MSG_WITH_FORMAT_STRING(
        "eventfd signal failed: %s (errno %d)", strerror(saved_errno),
        saved_errno);
    return RMW_RET_ERROR;
  }
  return RMW_RET_OK;
}

rmw_ret_t rmw_publisher_event_init(rmw_event_t *rmw_event,
                                   const rmw_publisher_t *publisher,
                                   rmw_event_type_t event_type) {
  if (!rmw_event || !publisher)
    return RMW_RET_INVALID_ARGUMENT;
  axon_publisher_data_t *data = (axon_publisher_data_t *)publisher->data;
  if (!data)
    return RMW_RET_INVALID_ARGUMENT;

  uint32_t kind = 0;
  switch (event_type) {
  case RMW_EVENT_LIVELINESS_LOST:
    kind = 0;
    break;
  case RMW_EVENT_OFFERED_DEADLINE_MISSED:
    kind = 2;
    break;
  case RMW_EVENT_OFFERED_QOS_INCOMPATIBLE:
    kind = 4;
    break;
  default:
    return RMW_RET_UNSUPPORTED;
  }

  uint64_t handle = axon_session_create_event(data->session_id, 0, kind);
  if (handle == 0)
    return RMW_RET_ERROR;

  axon_event_data_t *ev =
      (axon_event_data_t *)rmw_allocate(sizeof(axon_event_data_t));
  if (!ev)
    return RMW_RET_BAD_ALLOC;
  ev->session_id = data->session_id;
  ev->event_handle = handle;
  ev->last_count = 0;
  ev->last_alive_count = 0;
  ev->last_not_alive_count = 0;

  rmw_event->data = ev;
  rmw_event->event_type = event_type;
  rmw_event->implementation_identifier = rmw_get_implementation_identifier();
  return RMW_RET_OK;
}

rmw_ret_t rmw_subscription_event_init(rmw_event_t *rmw_event,
                                      const rmw_subscription_t *subscription,
                                      rmw_event_type_t event_type) {
  if (!rmw_event || !subscription)
    return RMW_RET_INVALID_ARGUMENT;
  axon_subscription_data_t *data =
      (axon_subscription_data_t *)subscription->data;
  if (!data)
    return RMW_RET_INVALID_ARGUMENT;

  uint32_t kind = 0;
  switch (event_type) {
  case RMW_EVENT_LIVELINESS_CHANGED:
    kind = 1;
    break;
  case RMW_EVENT_REQUESTED_DEADLINE_MISSED:
    kind = 2;
    break;
  case RMW_EVENT_MESSAGE_LOST:
    kind = 3;
    break;
  case RMW_EVENT_REQUESTED_QOS_INCOMPATIBLE:
    kind = 4;
    break;
  default:
    return RMW_RET_UNSUPPORTED;
  }

  uint64_t handle = axon_session_create_event(data->session_id, 0, kind);
  if (handle == 0)
    return RMW_RET_ERROR;

  axon_event_data_t *ev =
      (axon_event_data_t *)rmw_allocate(sizeof(axon_event_data_t));
  if (!ev)
    return RMW_RET_BAD_ALLOC;
  ev->session_id = data->session_id;
  ev->event_handle = handle;
  ev->last_count = 0;
  ev->last_alive_count = 0;
  ev->last_not_alive_count = 0;

  rmw_event->data = ev;
  rmw_event->event_type = event_type;
  rmw_event->implementation_identifier = rmw_get_implementation_identifier();
  return RMW_RET_OK;
}

rmw_ret_t rmw_subscription_set_content_filter(
    rmw_subscription_t *subscription,
    const rmw_subscription_content_filter_options_t *options) {
  if (!subscription || !options)
    return RMW_RET_INVALID_ARGUMENT;
  auto *sub_data = static_cast<axon_subscription_data_t *>(subscription->data);
  uint64_t sid = sub_data->session_id;

  // Cache the expression locally for fast access during rmw_take
  if (sub_data->content_filter_expression) {
    free(sub_data->content_filter_expression);
    sub_data->content_filter_expression = nullptr;
  }
  if (options->filter_expression && options->filter_expression[0] != '\0') {
    sub_data->content_filter_expression = strdup(options->filter_expression);
  }

  const char *name = "";
  const char *expr = options->filter_expression ? options->filter_expression : "";
  if (axon_session_set_content_filter(sid, sub_data->topic_name, name, expr,
                                      nullptr, nullptr, 0) != 0)
    return RMW_RET_ERROR;
  return RMW_RET_OK;
}

rmw_ret_t rmw_subscription_get_content_filter(
    const rmw_subscription_t *subscription, rcutils_allocator_t *allocator,
    rmw_subscription_content_filter_options_t *options) {
  if (!subscription || !allocator || !options)
    return RMW_RET_INVALID_ARGUMENT;
  auto *sub_data = static_cast<axon_subscription_data_t *>(subscription->data);
  uint64_t sid = sub_data->session_id;
  uint8_t name_buf[256] = {0};
  uint8_t expr_buf[1024] = {0};
  if (axon_session_get_content_filter(sid, sub_data->topic_name, name_buf,
                                      sizeof(name_buf), expr_buf,
                                      sizeof(expr_buf)) != 0)
    return RMW_RET_ERROR;
  size_t expr_len = strlen(reinterpret_cast<const char *>(expr_buf));
  options->filter_expression =
      static_cast<char *>(allocator->allocate(expr_len + 1, allocator->state));
  if (!options->filter_expression)
    return RMW_RET_BAD_ALLOC;
  strcpy(options->filter_expression, reinterpret_cast<const char *>(expr_buf));
  rcutils_ret_t _rc =
      rcutils_string_array_init(&options->expression_parameters, 0, allocator);
  (void)_rc;
  return RMW_RET_OK;
}

bool rmw_event_type_is_supported(rmw_event_type_t rmw_event_type) {
  switch (rmw_event_type) {
  case RMW_EVENT_LIVELINESS_LOST:
  case RMW_EVENT_LIVELINESS_CHANGED:
  case RMW_EVENT_REQUESTED_DEADLINE_MISSED:
  case RMW_EVENT_OFFERED_DEADLINE_MISSED:
  case RMW_EVENT_MESSAGE_LOST:
  case RMW_EVENT_OFFERED_QOS_INCOMPATIBLE:
  case RMW_EVENT_REQUESTED_QOS_INCOMPATIBLE:
    return true;
  default:
    return false;
  }
}

rmw_ret_t rmw_event_set_callback(rmw_event_t *event,
                                 rmw_event_callback_t callback,
                                 const void *user_data) {
  (void)event;
  (void)callback;
  (void)user_data;
  return RMW_RET_OK;
}

rmw_ret_t rmw_event_fini(rmw_event_t *event) {
  if (!event)
    return RMW_RET_INVALID_ARGUMENT;
  if (event->data) {
    axon_event_data_t *ev = static_cast<axon_event_data_t *>(event->data);
    if (ev->event_handle != 0) {
      axon_session_destroy_event(ev->session_id, ev->event_handle);
    }
    rmw_free(ev);
  }
  event->data = nullptr;
  event->implementation_identifier = nullptr;
  return RMW_RET_OK;
}

bool rmw_feature_supported(rmw_feature_t feature) {
  switch (feature) {
  case RMW_FEATURE_MESSAGE_INFO_PUBLICATION_SEQUENCE_NUMBER:
  case RMW_FEATURE_MESSAGE_INFO_RECEPTION_SEQUENCE_NUMBER:
    return false;
#ifdef RMW_MIDDLEWARE_SUPPORTS_TYPE_DISCOVERY
  case RMW_MIDDLEWARE_SUPPORTS_TYPE_DISCOVERY:
    return false;
#endif
#ifdef RMW_MIDDLEWARE_CAN_TAKE_DYNAMIC_MESSAGE
  case RMW_MIDDLEWARE_CAN_TAKE_DYNAMIC_MESSAGE:
    return false;
#endif
  default:
    return false;
  }
}
