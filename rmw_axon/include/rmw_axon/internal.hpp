#ifndef RMW_AXON__INTERNAL_HPP_
#define RMW_AXON__INTERNAL_HPP_

#include "rmw_axon/rmw_axon.h"

#include "rmw/allocators.h"
#if __has_include("rmw/dynamic_message_type_support.h")
#include "rmw/dynamic_message_type_support.h"
#endif
#include "rmw/error_handling.h"
#include "rmw/features.h"
#include "rmw/get_network_flow_endpoints.h"
#include "rmw/get_node_info_and_types.h"
#include "rmw/get_service_names_and_types.h"
#include "rmw/get_topic_endpoint_info.h"
#include "rmw/get_topic_names_and_types.h"
#include "rmw/rmw.h"
#include "rmw/serialized_message.h"

// ROS 2 Humble compatibility: define MANUAL_BY_PARTICIPANT if not available
#ifndef RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_PARTICIPANT
#define RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_PARTICIPANT (rmw_qos_liveliness_policy_t)2
#endif
#include "rmw/topic_endpoint_info_array.h"
#include "rmw/types.h"

#include "rosidl_runtime_c/message_type_support_struct.h"
#include "rosidl_runtime_c/service_type_support_struct.h"
#include "rosidl_typesupport_c/identifier.h"
#include "rosidl_typesupport_c/message_type_support_dispatch.h"
#include "rosidl_typesupport_c/service_type_support_dispatch.h"
#include "rosidl_typesupport_cpp/message_type_support_dispatch.hpp"
#include "rosidl_typesupport_cpp/service_type_support_dispatch.hpp"
#include "rosidl_typesupport_fastrtps_c/identifier.h"
#include "rosidl_typesupport_fastrtps_cpp/identifier.hpp"
#include "rosidl_typesupport_fastrtps_cpp/message_type_support.h"
#include "rosidl_typesupport_fastrtps_cpp/service_type_support.h"

#include "fastcdr/Cdr.h"
#include "fastcdr/FastBuffer.h"
#include "fastcdr/config.h"

// ─── FastCDR version compatibility
// ────────────────────────────────────────────
#if FASTCDR_VERSION_MAJOR >= 2
#define AXON_FASTCDR_CDR_TYPE eprosima::fastcdr::DDS_CDR
#define AXON_FASTCDR_GET_LENGTH(cdr) (cdr).get_serialized_data_length()
#else
#define AXON_FASTCDR_CDR_TYPE eprosima::fastcdr::Cdr::DDS_CDR
#define AXON_FASTCDR_GET_LENGTH(cdr) (cdr).getSerializedDataLength()
#endif

#include "rosidl_typesupport_introspection_c/identifier.h"
#include "rosidl_typesupport_introspection_c/message_introspection.h"
#include "rosidl_typesupport_introspection_c/field_types.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <limits>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

struct axon_qos_duration_wire_t {
  uint64_t sec;
  uint32_t nsec;
};

static inline bool axon_qos_duration_is_unbounded(const rmw_time_t &time) {
  // RMW_DURATION_UNSPECIFIED is {0, 0}. RMW_DURATION_INFINITE is INT64_MAX
  // nanoseconds split as seconds/nanoseconds in rmw_time_t.
  const uint64_t infinite_sec = 9223372036ULL;
  const uint64_t infinite_nsec = 854775807ULL;
  return (time.sec == 0 && time.nsec == 0) ||
         time.sec > infinite_sec ||
         (time.sec == infinite_sec && time.nsec >= infinite_nsec);
}

static inline axon_qos_duration_wire_t
axon_qos_duration_to_wire(const rmw_time_t &time) {
  if (axon_qos_duration_is_unbounded(time)) {
    return {0, 0};
  }
  uint64_t sec = time.sec + (time.nsec / 1000000000ULL);
  uint64_t nsec = time.nsec % 1000000000ULL;
  rmw_time_t normalized{sec, nsec};
  if (axon_qos_duration_is_unbounded(normalized)) {
    return {0, 0};
  }
  return {sec, static_cast<uint32_t>(nsec)};
}

static inline uint64_t
axon_qos_duration_total_ns_or_zero(const rmw_time_t &time) {
  axon_qos_duration_wire_t duration = axon_qos_duration_to_wire(time);
  if (duration.sec == 0 && duration.nsec == 0) {
    return 0;
  }
  return duration.sec * 1000000000ULL + duration.nsec;
}

static inline int32_t
axon_qos_liveliness_to_wire(rmw_qos_liveliness_policy_t liveliness) {
  if (liveliness == RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_TOPIC) {
    return 1;
  }
  if (liveliness == RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_PARTICIPANT) {
    return 2;
  }
  return 0;
}

// ─── Logging ─────────────────────────────────────────────────────────────────

static inline long axon_usec() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000000L + tv.tv_usec;
}

#define AXON_LOG(fmt, ...)                                                     \
  do {                                                                         \
    fprintf(stderr, "AXON [%ld] %s: " fmt "\n", axon_usec(), __func__,         \
            ##__VA_ARGS__);                                                    \
  } while (0)

static inline bool axon_trace_fds_enabled() {
  static int enabled = []() {
    const char *value = getenv("AXON_TRACE_FDS");
    return (value && value[0] != '\0' && strcmp(value, "0") != 0) ? 1 : 0;
  }();
  return enabled != 0;
}

static inline void axon_trace_fd_event(const char *action, const char *kind,
                                       int fd, const char *name) {
  if (!axon_trace_fds_enabled()) {
    return;
  }
  fprintf(stderr, "[rmw_axon_fd] %s kind=%s fd=%d name=%s\n", action, kind, fd,
          name ? name : "");
}

static inline bool axon_trace_ros_enabled() {
  static int enabled = []() {
    const char *value = getenv("AXON_TRACE");
    return (value && value[0] != '\0' && strcmp(value, "0") != 0) ? 1 : 0;
  }();
  return enabled != 0;
}

#define AXON_TRACE_ROS(fmt, ...)                                               \
  do {                                                                         \
    if (axon_trace_ros_enabled()) {                                           \
      fprintf(stderr, "[axon_trace_ros] ts_us=%ld pid=%d fn=%s " fmt "\n",  \
              axon_usec(), static_cast<int>(getpid()), __func__,              \
              ##__VA_ARGS__);                                                  \
    }                                                                            \
  } while (0)

// ─── FFI: Rust axon_core (multi-session API) ────────────────────────────────

extern "C" {
extern int64_t axon_session_create(int32_t domain_id);
extern int32_t axon_session_shutdown(uint64_t session_id);
extern int32_t axon_session_destroy(uint64_t session_id);
extern int32_t axon_session_set_node_name(uint64_t session_id, const char *name,
                                          const char *namespace_);
extern int32_t axon_session_register_graph_event_fd(uint64_t session_id,
                                                    int event_fd);
extern int32_t axon_session_unregister_graph_event_fd(uint64_t session_id,
                                                      int event_fd);
extern int32_t
axon_session_create_publisher(uint64_t session_id, const char *topic,
                              const char *topic_type, int32_t reliability,
                              int32_t history_kind, int32_t depth);
extern int32_t
axon_session_create_publisher_with_qos(uint64_t session_id, const char *topic,
                                        const char *topic_type,
                                        int32_t reliability, int32_t durability,
                                        int32_t history_kind, int32_t depth,
                                        uint64_t deadline_s, uint32_t deadline_ns,
                                        uint64_t lifespan_s, uint32_t lifespan_ns,
                                        int32_t liveliness,
                                        uint64_t liveliness_lease_s,
                                        uint32_t liveliness_lease_ns);
extern int32_t axon_session_destroy_publisher(uint64_t session_id,
                                              const char *topic);
extern int64_t
axon_session_create_subscription(uint64_t session_id, const char *topic,
                                 const char *topic_type, int32_t reliability,
                                 int32_t history_kind, int32_t depth,
                                 uint64_t *initial_seq);
extern int64_t axon_session_create_subscription_with_qos(
    uint64_t session_id, const char *topic, const char *topic_type,
    int32_t reliability, int32_t durability, int32_t history_kind,
    int32_t depth,
    uint64_t deadline_s, uint32_t deadline_ns,
    uint64_t lifespan_s, uint32_t lifespan_ns,
    int32_t liveliness,
    uint64_t liveliness_lease_s, uint32_t liveliness_lease_ns,
    uint64_t *initial_seq);
extern int32_t axon_session_destroy_subscription(uint64_t session_id,
                                                 const char *topic);
extern char *axon_session_get_topic_type(uint64_t session_id,
                                         const char *topic_name);
extern int64_t axon_session_publish(uint64_t session_id, const char *topic,
                                    const uint8_t *data, uint32_t len);
extern int32_t axon_session_take(uint64_t session_id, const char *topic,
                                 uint64_t seq, uint8_t *out, uint32_t *out_len);
extern int32_t axon_session_take_next(uint64_t session_id, const char *topic,
                                      uint64_t *seq_inout, uint8_t *out,
                                      uint32_t *out_len);
extern int32_t axon_session_create_service(uint64_t session_id,
                                           const char *service_name,
                                           const char *service_type,
                                           int32_t reliability);
extern int32_t axon_session_create_service_with_qos(
    uint64_t session_id, const char *service_name, const char *service_type,
    int32_t reliability, int32_t durability, int32_t history_kind, int32_t depth,
    uint64_t deadline_s, uint32_t deadline_ns,
    uint64_t lifespan_s, uint32_t lifespan_ns,
    int32_t liveliness, uint64_t liveliness_lease_s, uint32_t liveliness_lease_ns);
extern int32_t axon_session_destroy_service(uint64_t session_id,
                                             const char *service_name);
extern int32_t axon_session_create_client(uint64_t session_id,
                                          const char *service_name,
                                          const char *service_type,
                                          int32_t reliability);
extern int32_t axon_session_create_client_with_qos(
    uint64_t session_id, const char *service_name, const char *service_type,
    int32_t reliability, int32_t durability, int32_t history_kind, int32_t depth,
    uint64_t deadline_s, uint32_t deadline_ns,
    uint64_t lifespan_s, uint32_t lifespan_ns,
    int32_t liveliness, uint64_t liveliness_lease_s, uint32_t liveliness_lease_ns);
extern int32_t axon_session_destroy_client(uint64_t session_id,
                                           const char *service_name);
extern int64_t axon_session_send_request(uint64_t session_id,
                                         const char *service_name,
                                         const uint8_t *data, uint32_t len);
extern int64_t axon_session_send_request_with_gid(
    uint64_t session_id, const char *service_name, const uint8_t *client_gid,
    const uint8_t *data, uint32_t len);
extern int32_t axon_session_take_request(uint64_t session_id,
                                         const char *service_name, uint64_t seq,
                                         uint8_t *out, uint32_t *out_len);
extern int32_t axon_session_take_request_with_info(
    uint64_t session_id, const char *service_name, uint64_t seq,
    uint8_t *out, uint32_t *out_len, uint8_t *client_gid_out,
    int64_t *request_sequence_out);
extern int64_t axon_session_send_response(uint64_t session_id,
                                          const char *service_name,
                                          const uint8_t *data, uint32_t len);
extern int64_t axon_session_send_response_with_info(
    uint64_t session_id, const char *service_name, const uint8_t *client_gid,
    int64_t request_sequence, const uint8_t *data, uint32_t len);
extern int32_t axon_session_take_response(uint64_t session_id,
                                          const char *service_name,
                                          uint64_t seq, uint8_t *out,
                                          uint32_t *out_len);
extern int32_t axon_session_take_response_for_client(
    uint64_t session_id, const char *service_name, uint64_t *next_seq_inout,
    const uint8_t *client_gid, uint8_t *out, uint32_t *out_len,
    int64_t *request_sequence_out);
extern int64_t axon_session_service_initial_seq(uint64_t session_id,
                                                 const char *service_name);
extern int64_t axon_session_client_initial_seq(uint64_t session_id,
                                                const char *service_name);
extern int32_t axon_session_get_node_names(uint64_t session_id, uint8_t *out,
                                           uint32_t out_len,
                                           uint32_t *count_out);
extern int32_t axon_session_get_node_names_with_namespaces(uint64_t session_id,
                                                           uint8_t *out,
                                                           uint32_t out_len,
                                                           uint32_t *count_out);
extern int32_t axon_session_get_topic_names(uint64_t session_id, uint8_t *out,
                                            uint32_t out_len,
                                            uint32_t *count_out);
extern int32_t axon_session_get_service_names_and_types(uint64_t session_id,
                                                        size_t *count,
                                                        char ***names,
                                                        char ***types);
extern int64_t axon_session_create_waitset(uint64_t session_id);
extern int32_t axon_session_destroy_waitset(uint64_t session_id,
                                            uint64_t ws_handle);
extern int64_t axon_session_service_request_eventfd(uint64_t session_id,
                                                    const char *service_name);
extern int64_t axon_session_service_response_eventfd(uint64_t session_id,
                                                     const char *service_name);
extern int32_t axon_session_count_publishers(uint64_t session_id,
                                             const char *topic_name,
                                             uint32_t *count_out);
extern int32_t axon_session_count_subscribers(uint64_t session_id,
                                              const char *topic_name,
                                              uint32_t *count_out);
extern int32_t axon_session_count_services(uint64_t session_id,
                                           const char *service_name,
                                           uint32_t *count_out);
extern int32_t axon_session_count_clients(uint64_t session_id,
                                          const char *service_name,
                                          uint32_t *count_out);
extern int32_t axon_session_count_matched_subs(uint64_t session_id,
                                               const char *topic_name,
                                               uint32_t *count_out);
extern int32_t axon_session_count_matched_pubs(uint64_t session_id,
                                               const char *topic_name,
                                               uint32_t *count_out);
extern int32_t axon_session_service_available(uint64_t session_id,
                                              const char *service_name,
                                              int32_t *available_out);
extern int32_t axon_session_data_available(uint64_t session_id,
                                           const char *topic_name,
                                           uint64_t next_seq);
extern int32_t axon_session_sync_routes(uint64_t session_id);
extern int32_t
axon_session_service_request_data_available(uint64_t session_id,
                                            const char *service_name,
                                            uint64_t next_seq);
extern int32_t
axon_session_service_response_data_available(uint64_t session_id,
                                             const char *service_name,
                                             uint64_t next_seq);
extern int32_t axon_session_get_serialized_message_size(uint64_t session_id,
                                                        const char *type_name,
                                                        size_t *size_out);
extern int32_t axon_session_get_node_names_with_enclaves(uint64_t session_id,
                                                         uint8_t *out,
                                                         uint32_t out_len,
                                                         uint32_t *count_out);
extern int32_t axon_session_take_serialized_message_with_info(
    uint64_t session_id, const char *topic, uint64_t seq, uint8_t *out,
    uint32_t *out_len, int64_t *source_timestamp, int64_t *received_timestamp,
    int64_t *sequence_number);
extern int32_t axon_session_take_serialized_message_with_info_next(
    uint64_t session_id, const char *topic, uint64_t *seq_inout, uint8_t *out,
    uint32_t *out_len, int64_t *source_timestamp, int64_t *received_timestamp,
    int64_t *sequence_number);
extern int32_t axon_session_get_publishers_by_node(uint64_t session_id,
                                                   const char *node_name,
                                                   const char *node_ns,
                                                   size_t *count, char ***names,
                                                   char ***types);
extern int32_t
axon_session_get_subscribers_by_node(uint64_t session_id, const char *node_name,
                                     const char *node_ns, size_t *count,
                                     char ***names, char ***types);
extern int32_t axon_session_get_services_by_node(uint64_t session_id,
                                                 const char *node_name,
                                                 const char *node_ns,
                                                 size_t *count, char ***names,
                                                 char ***types);
extern int32_t axon_session_get_clients_by_node(uint64_t session_id,
                                                const char *node_name,
                                                const char *node_ns,
                                                size_t *count, char ***names,
                                                char ***types);
extern int32_t axon_session_publisher_actual_qos(uint64_t session_id,
                                                 const char *topic_name,
                                                 int32_t *reliability_out,
                                                 int32_t *durability_out);
extern int32_t axon_session_publisher_actual_qos_full(
    uint64_t session_id, const char *topic_name, int32_t *reliability_out,
    int32_t *durability_out, int32_t *history_out, size_t *depth_out,
    int32_t *liveliness_out, uint64_t *liveliness_lease_s_out,
    uint32_t *liveliness_lease_ns_out, uint64_t *deadline_s_out,
    uint32_t *deadline_ns_out, uint64_t *lifespan_s_out,
    uint32_t *lifespan_ns_out);
extern int32_t axon_session_subscription_actual_qos(uint64_t session_id,
                                                    const char *topic_name,
                                                    int32_t *reliability_out,
                                                    int32_t *durability_out);
extern int32_t axon_session_subscription_actual_qos_full(
    uint64_t session_id, const char *topic_name, int32_t *reliability_out,
    int32_t *durability_out, int32_t *history_out, size_t *depth_out,
    int32_t *liveliness_out, uint64_t *liveliness_lease_s_out,
    uint32_t *liveliness_lease_ns_out, uint64_t *deadline_s_out,
    uint32_t *deadline_ns_out, uint64_t *lifespan_s_out,
    uint32_t *lifespan_ns_out);
extern int32_t axon_session_assert_liveliness(uint64_t session_id);
extern int32_t axon_session_publisher_flow_endpoints(uint64_t session_id,
                                                     const char *topic_name,
                                                     size_t *count,
                                                     char ***addrs);
extern int32_t axon_session_subscription_flow_endpoints(uint64_t session_id,
                                                        const char *topic_name,
                                                        size_t *count,
                                                        char ***addrs);
extern uint8_t *axon_session_borrow_loaned(uint64_t session_id,
                                           const char *topic, size_t max_size);
extern int32_t axon_session_publish_loaned(uint64_t session_id,
                                           const char *topic,
                                           const uint8_t *ptr, size_t size);
extern const uint8_t *axon_session_take_loaned(uint64_t session_id,
                                               const char *topic, uint64_t seq,
                                               size_t *size_out);
extern int32_t axon_session_return_loaned(uint64_t session_id,
                                          const char *topic, const uint8_t *ptr,
                                          size_t size);
extern int32_t axon_session_set_content_filter(
    uint64_t session_id, const char *topic, const char *name,
    const char *expression, const char **params_keys,
    const char **params_values, size_t params_count);
extern int32_t axon_session_get_content_filter(
    uint64_t session_id, const char *topic, uint8_t *name_out,
    uint32_t name_len, uint8_t *expression_out, uint32_t expression_len);
extern uint64_t axon_session_create_event(uint64_t session_id,
                                          uint64_t entity_handle,
                                          uint32_t event_kind);
extern int32_t axon_session_take_event(uint64_t session_id,
                                       uint64_t event_handle,
                                       int64_t *count_out,
                                       int64_t *timestamp_out,
                                       int64_t *alive_count_out,
                                       int64_t *not_alive_count_out);
extern int32_t axon_session_destroy_event(uint64_t session_id,
                                          uint64_t event_handle);
extern int64_t axon_session_event_monitor_fd(uint64_t session_id);
extern void axon_session_free_string(char *s);

// ─── Endpoint info introspection ──────────────────────────────────────────

extern char *axon_session_get_node_name(uint64_t session_id);
extern char *axon_session_get_node_namespace(uint64_t session_id);
extern int32_t axon_session_publisher_gid(uint64_t session_id,
                                          const char *topic_name,
                                          uint8_t *gid_out);
extern int32_t axon_session_subscription_gid(uint64_t session_id,
                                             const char *topic_name,
                                             uint8_t *gid_out);
extern int32_t axon_session_client_gid(uint64_t session_id,
                                       const char *service_name,
                                       uint8_t *gid_out);
extern int32_t axon_session_get_publishers_info(uint64_t session_id,
                                                const char *topic_name,
                                                uint32_t *count_out,
                                                uint8_t *info_buf,
                                                uint32_t info_buf_len);
extern int32_t axon_session_get_subscriptions_info(uint64_t session_id,
                                                   const char *topic_name,
                                                   uint32_t *count_out,
                                                   uint8_t *info_buf,
                                                    uint32_t info_buf_len);
extern int32_t axon_session_service_qos(uint64_t session_id, const char *service_name,
                                        int32_t role, int32_t *rel, int32_t *dur,
                                        int32_t *history, size_t *depth,
                                        int32_t *liveliness,
                                        uint64_t *ll_s, uint32_t *ll_ns,
                                        uint64_t *dl_s, uint32_t *dl_ns,
                                        uint64_t *ls_s, uint32_t *ls_ns);
}

// ─── Data types ──────────────────────────────────────────────────────────────

typedef struct axon_context_impl_t {
  uint64_t session_id;
  bool shutdown_called;
} axon_context_impl_t;

typedef struct axon_node_data {
  uint64_t session_id;
  rmw_guard_condition_t *graph_gc;
} axon_node_data_t;

typedef struct axon_publisher_data {
  uint64_t session_id;
  char *topic_name;
  char *topic_type;
  const rosidl_message_type_support_t *type_support;
} axon_publisher_data_t;

typedef struct axon_subscription_data {
  uint64_t session_id;
  char *topic_name;
  char *topic_type;
  uint64_t next_seq;
  int eventfd;
  const rosidl_message_type_support_t *type_support;
  /// Cached content filter expression (nullptr if none).
  char *content_filter_expression;
} axon_subscription_data_t;

typedef struct axon_service_data {
  uint64_t session_id;
  char *service_name;
  uint64_t next_seq;
  int request_eventfd;
  const rosidl_service_type_support_t *type_support;
} axon_service_data_t;

typedef struct axon_client_data {
  uint64_t session_id;
  char *service_name;
  uint64_t next_seq;
  int response_eventfd;
  /// Unique endpoint identity used to correlate multiplexed service responses.
  uint8_t client_gid[16];
  const rosidl_service_type_support_t *type_support;
} axon_client_data_t;

typedef struct axon_waitset_data {
  uint64_t session_id;
  int64_t ws_handle;
} axon_waitset_data_t;

typedef struct axon_guard_condition_data {
  int event_fd;
  bool owns_event_fd;
  std::atomic_bool triggered;
} axon_guard_condition_data_t;

bool axon_guard_condition_use_dedicated_eventfd(
    rmw_guard_condition_t *guard_condition);

typedef struct axon_event_data {
  uint64_t session_id;
  uint64_t event_handle;
  int64_t last_count;
  int64_t last_alive_count;
  int64_t last_not_alive_count;
} axon_event_data_t;

typedef struct axon_loaned_header {
  uint64_t session_id;
  char *topic_name;
  size_t buffer_size;
} axon_loaned_header_t;

// ─── Shared helpers ─────────────────────────────────────────────────────────

static inline uint64_t get_session_id(rmw_context_t *context) {
  if (!context || !context->impl)
    return 0;
  return ((axon_context_impl_t *)context->impl)->session_id;
}

static inline const message_type_support_callbacks_t *
get_fastrtps_callbacks(const rosidl_message_type_support_t *type_support) {
  const rosidl_message_type_support_t *ts =
      rosidl_typesupport_c__get_message_typesupport_handle_function(
          type_support, rosidl_typesupport_fastrtps_c__identifier);
  if (ts) {
    return static_cast<const message_type_support_callbacks_t *>(ts->data);
  }
  rcutils_reset_error();
  ts = rosidl_typesupport_cpp::get_message_typesupport_handle_function(
      type_support, rosidl_typesupport_fastrtps_cpp::typesupport_identifier);
  if (ts) {
    return static_cast<const message_type_support_callbacks_t *>(ts->data);
  }
  rcutils_reset_error();
  return NULL;
}

static inline std::string
get_message_type_name(const rosidl_message_type_support_t *type_support) {
  if (!type_support) {
    return "unknown";
  }
  const message_type_support_callbacks_t *callbacks = nullptr;
  const rosidl_message_type_support_t *ts =
      rosidl_typesupport_c__get_message_typesupport_handle_function(
          type_support, rosidl_typesupport_fastrtps_c__identifier);
  if (ts) {
    callbacks = static_cast<const message_type_support_callbacks_t *>(ts->data);
  }
  if (!callbacks) {
    rcutils_reset_error();
    ts = rosidl_typesupport_cpp::get_message_typesupport_handle_function(
        type_support, rosidl_typesupport_fastrtps_cpp::typesupport_identifier);
    if (ts) {
      callbacks =
          static_cast<const message_type_support_callbacks_t *>(ts->data);
    }
  }
  rcutils_reset_error();
  if (!callbacks || !callbacks->message_name_ ||
      !callbacks->message_namespace_) {
    return "unknown";
  }
  std::string ns = callbacks->message_namespace_;
  for (size_t pos = ns.find("::"); pos != std::string::npos;
       pos = ns.find("::", pos)) {
    ns.replace(pos, 2, "/");
  }
  return ns + "/" + callbacks->message_name_;
}

static inline std::string
get_service_type_name(const rosidl_service_type_support_t *type_support) {
  if (!type_support) {
    return "unknown";
  }
  const service_type_support_callbacks_t *callbacks = nullptr;
  const rosidl_service_type_support_t *ts =
      rosidl_typesupport_c__get_service_typesupport_handle_function(
          type_support, rosidl_typesupport_fastrtps_c__identifier);
  if (ts) {
    callbacks = static_cast<const service_type_support_callbacks_t *>(ts->data);
  }
  if (!callbacks) {
    rcutils_reset_error();
    ts = rosidl_typesupport_cpp::get_service_typesupport_handle_function(
        type_support, rosidl_typesupport_fastrtps_cpp::typesupport_identifier);
    if (ts) {
      callbacks =
          static_cast<const service_type_support_callbacks_t *>(ts->data);
    }
  }
  rcutils_reset_error();
  if (!callbacks || !callbacks->service_name_ ||
      !callbacks->service_namespace_) {
    return "unknown";
  }
  std::string ns = callbacks->service_namespace_;
  for (size_t pos = ns.find("::"); pos != std::string::npos;
       pos = ns.find("::", pos)) {
    ns.replace(pos, 2, "/");
  }
  return ns + "/" + callbacks->service_name_;
}

static inline bool
serialize_message(const message_type_support_callbacks_t *callbacks,
                  const void *ros_message, uint8_t *buffer, uint32_t *size) {
  try {
    eprosima::fastcdr::FastBuffer fast_buffer(reinterpret_cast<char *>(buffer),
                                              *size);
    eprosima::fastcdr::Cdr cdr(fast_buffer,
                               eprosima::fastcdr::Cdr::DEFAULT_ENDIAN,
                               AXON_FASTCDR_CDR_TYPE);
    if (!callbacks->cdr_serialize(ros_message, cdr)) {
      return false;
    }
    *size = static_cast<uint32_t>(AXON_FASTCDR_GET_LENGTH(cdr));
    return true;
  } catch (...) {
    return false;
  }
}

static inline size_t axon_serialized_size_for_message(
    const message_type_support_callbacks_t *callbacks, const void *ros_message,
    size_t fallback_size) {
  if (callbacks && callbacks->get_serialized_size && ros_message) {
    try {
      size_t exact_size = callbacks->get_serialized_size(ros_message);
      if (exact_size > 0) {
        return exact_size;
      }
    } catch (...) {
    }
  }

  if (callbacks && callbacks->max_serialized_size) {
    try {
      char bounds_info = 0;
      size_t max_size = callbacks->max_serialized_size(bounds_info);
      if (max_size > 0) {
        return max_size;
      }
    } catch (...) {
    }
  }

  return fallback_size;
}

static inline bool axon_grow_serialization_buffer(uint8_t **buffer,
                                                  uint32_t *capacity,
                                                  uint32_t min_capacity) {
  uint32_t next = *capacity;
  if (next == 0) {
    next = 4096;
  }
  while (next < min_capacity) {
    if (next > std::numeric_limits<uint32_t>::max() / 2) {
      return false;
    }
    next *= 2;
  }
  if (next == *capacity) {
    if (next > std::numeric_limits<uint32_t>::max() / 2) {
      return false;
    }
    next *= 2;
  }
  uint8_t *new_buffer = static_cast<uint8_t *>(realloc(*buffer, next));
  if (!new_buffer) {
    return false;
  }
  *buffer = new_buffer;
  *capacity = next;
  return true;
}

static inline rmw_ret_t
axon_ensure_serialized_message_capacity(rmw_serialized_message_t *message,
                                        size_t min_capacity) {
  if (!message) {
    return RMW_RET_INVALID_ARGUMENT;
  }
  if (min_capacity == 0) {
    min_capacity = 1;
  }

  rcutils_allocator_t alloc = rcutils_get_default_allocator();
  if (message->buffer == nullptr || message->buffer_capacity == 0) {
    return rmw_serialized_message_init(message, min_capacity, &alloc);
  }
  if (message->buffer_capacity < min_capacity) {
    return rmw_serialized_message_resize(message, min_capacity);
  }
  return RMW_RET_OK;
}

static inline bool
deserialize_message(const message_type_support_callbacks_t *callbacks,
                    const uint8_t *buffer, uint32_t size, void *ros_message) {
  try {
    eprosima::fastcdr::FastBuffer fast_buffer(
        const_cast<char *>(reinterpret_cast<const char *>(buffer)), size);
    eprosima::fastcdr::Cdr cdr(fast_buffer,
                               eprosima::fastcdr::Cdr::DEFAULT_ENDIAN,
                               AXON_FASTCDR_CDR_TYPE);
    return callbacks->cdr_deserialize(cdr, ros_message);
  } catch (...) {
    return false;
  }
}

static inline const message_type_support_callbacks_t *
get_service_msg_callbacks(const rosidl_service_type_support_t *service_ts,
                          bool is_request) {
  const rosidl_service_type_support_t *ts =
      rosidl_typesupport_c__get_service_typesupport_handle_function(
          service_ts, rosidl_typesupport_fastrtps_c__identifier);
  if (ts) {
    const service_type_support_callbacks_t *cb =
        static_cast<const service_type_support_callbacks_t *>(ts->data);
    if (cb) {
      return get_fastrtps_callbacks(is_request ? cb->request_members_
                                               : cb->response_members_);
    }
  }
  rcutils_reset_error();
  ts = rosidl_typesupport_cpp::get_service_typesupport_handle_function(
      service_ts, rosidl_typesupport_fastrtps_cpp::typesupport_identifier);
  if (ts) {
    const service_type_support_callbacks_t *cb =
        static_cast<const service_type_support_callbacks_t *>(ts->data);
    if (cb) {
      return get_fastrtps_callbacks(is_request ? cb->request_members_
                                               : cb->response_members_);
    }
  }
  rcutils_reset_error();
  return NULL;
}

// ─── Content filter helpers ──────────────────────────────────────────────────

/// Numeric comparison operators for filter expressions.
enum class FilterOp { EQ, NE, LT, GT, LE, GE };

/// A single constraint parsed from a filter expression (e.g. "x > 5").
struct FilterConstraint {
  std::string field_name;
  FilterOp op;
  enum ValueType { INT64, DOUBLE, STRING } value_type;
  int64_t int_val;
  double float_val;
  std::string str_val;
};

/// Parse a single constraint expression like "field OP value".
/// Returns true on success.
static inline bool
parse_single_constraint(const std::string &expr, FilterConstraint &c) {
  // Find operator
  const char *ops[] = {">=", "<=", "!=", "=", ">", "<"};
  size_t op_pos = std::string::npos;
  size_t op_len = 0;
  FilterOp op = FilterOp::EQ;
  for (auto &o : ops) {
    size_t p = expr.find(o);
    if (p != std::string::npos) {
      op_pos = p;
      op_len = strlen(o);
      if (strcmp(o, ">=") == 0) op = FilterOp::GE;
      else if (strcmp(o, "<=") == 0) op = FilterOp::LE;
      else if (strcmp(o, "!=") == 0) op = FilterOp::NE;
      else if (strcmp(o, "=") == 0) op = FilterOp::EQ;
      else if (strcmp(o, ">") == 0) op = FilterOp::GT;
      else if (strcmp(o, "<") == 0) op = FilterOp::LT;
      break;
    }
  }
  if (op_pos == std::string::npos) return false;
  c.op = op;
  c.field_name = expr.substr(0, op_pos);
  // Trim trailing whitespace from field name
  while (!c.field_name.empty() && c.field_name.back() == ' ')
    c.field_name.pop_back();
  std::string val_str = expr.substr(op_pos + op_len);
  // Trim leading whitespace from value
  while (!val_str.empty() && val_str.front() == ' ')
    val_str.erase(val_str.begin());
  // Detect value type
  if (val_str.size() >= 2 && val_str.front() == '"' && val_str.back() == '"') {
    c.value_type = FilterConstraint::STRING;
    c.str_val = val_str.substr(1, val_str.size() - 2);
  } else if (val_str.find('.') != std::string::npos) {
    c.value_type = FilterConstraint::DOUBLE;
    c.float_val = std::stod(val_str);
  } else {
    c.value_type = FilterConstraint::INT64;
    c.int_val = std::stoll(val_str);
  }
  return true;
}

/// Parse a full filter expression (e.g. "x > 5 AND y < 10") into constraints.
/// Returns true if parsing succeeds, false on syntax error.
/// `conjunction_and` is set to true for AND, false for OR (multiple parts use
/// the same conjunction throughout).
static inline bool
parse_filter_expression(const std::string &expression,
                        std::vector<FilterConstraint> &constraints,
                        bool &conjunction_and) {
  constraints.clear();
  if (expression.empty()) return true;
  // Normalize: collapse multiple spaces
  std::string norm;
  bool in_space = false;
  for (char ch : expression) {
    if (ch == ' ') {
      if (!in_space) { norm += ' '; in_space = true; }
    } else {
      norm += ch;
      in_space = false;
    }
  }
  // Trim
  while (!norm.empty() && norm.front() == ' ') norm.erase(norm.begin());
  while (!norm.empty() && norm.back() == ' ') norm.pop_back();
  if (norm.empty()) return true;

  // Split on " OR " first (lower precedence)
  size_t or_pos = norm.find(" OR ");
  if (or_pos != std::string::npos) {
    conjunction_and = false;
    size_t start = 0;
    while (true) {
      size_t end = norm.find(" OR ", start);
      std::string part = (end == std::string::npos)
          ? norm.substr(start) : norm.substr(start, end - start);
      // Parse part which may contain AND
      size_t and_pos = part.find(" AND ");
      if (and_pos != std::string::npos) {
        // This OR-branch has AND sub-constraints
        size_t s = 0;
        while (true) {
          size_t e = part.find(" AND ", s);
          FilterConstraint c;
          if (!parse_single_constraint(
                  (e == std::string::npos) ? part.substr(s)
                                           : part.substr(s, e - s), c))
            return false;
          constraints.push_back(c);
          if (e == std::string::npos) break;
          s = e + 5;
        }
      } else {
        FilterConstraint c;
        if (!parse_single_constraint(part, c)) return false;
        constraints.push_back(c);
      }
      if (end == std::string::npos) break;
      start = end + 4;
    }
    return true;
  }

  // No OR found, split on AND
  conjunction_and = true;
  size_t start = 0;
  while (true) {
    size_t end = norm.find(" AND ", start);
    FilterConstraint c;
    if (!parse_single_constraint(
            (end == std::string::npos) ? norm.substr(start)
                                       : norm.substr(start, end - start), c))
      return false;
    constraints.push_back(c);
    if (end == std::string::npos) break;
    start = end + 5;
  }
  return true;
}

/// Get introspection members for a type support, or NULL if unavailable.
static inline const rosidl_typesupport_introspection_c__MessageMembers *
get_introspection_members(const rosidl_message_type_support_t *type_support) {
  if (!type_support) return NULL;
  const rosidl_message_type_support_t *ts =
      rosidl_typesupport_c__get_message_typesupport_handle_function(
          type_support, rosidl_typesupport_introspection_c__identifier);
  if (ts) {
    return static_cast<const rosidl_typesupport_introspection_c__MessageMembers *>(
        ts->data);
  }
  rcutils_reset_error();
  return NULL;
}

/// Read a field value from a ROS message struct using introspection metadata.
/// Returns true if the field was found and read.
static inline bool
read_field_value(const void *ros_message,
                 const rosidl_typesupport_introspection_c__MessageMember &member,
                 FilterConstraint::ValueType &out_type,
                 int64_t &out_int, double &out_double, std::string &out_str) {
  const uint8_t *base = static_cast<const uint8_t *>(ros_message) + member.offset_;
  switch (member.type_id_) {
    case rosidl_typesupport_introspection_c__ROS_TYPE_BOOL:
      out_type = FilterConstraint::INT64;
      out_int = *reinterpret_cast<const bool *>(base) ? 1 : 0;
      return true;
    case rosidl_typesupport_introspection_c__ROS_TYPE_OCTET:
    case rosidl_typesupport_introspection_c__ROS_TYPE_UINT8:
      out_type = FilterConstraint::INT64;
      out_int = *reinterpret_cast<const uint8_t *>(base);
      return true;
    case rosidl_typesupport_introspection_c__ROS_TYPE_INT8:
    case rosidl_typesupport_introspection_c__ROS_TYPE_CHAR:
      out_type = FilterConstraint::INT64;
      out_int = *reinterpret_cast<const int8_t *>(base);
      return true;
    case rosidl_typesupport_introspection_c__ROS_TYPE_UINT16:
      out_type = FilterConstraint::INT64;
      out_int = *reinterpret_cast<const uint16_t *>(base);
      return true;
    case rosidl_typesupport_introspection_c__ROS_TYPE_INT16:
      out_type = FilterConstraint::INT64;
      out_int = *reinterpret_cast<const int16_t *>(base);
      return true;
    case rosidl_typesupport_introspection_c__ROS_TYPE_UINT32:
      out_type = FilterConstraint::INT64;
      out_int = *reinterpret_cast<const uint32_t *>(base);
      return true;
    case rosidl_typesupport_introspection_c__ROS_TYPE_INT32:
      out_type = FilterConstraint::INT64;
      out_int = *reinterpret_cast<const int32_t *>(base);
      return true;
    case rosidl_typesupport_introspection_c__ROS_TYPE_UINT64:
      out_type = FilterConstraint::INT64;
      out_int = static_cast<int64_t>(*reinterpret_cast<const uint64_t *>(base));
      return true;
    case rosidl_typesupport_introspection_c__ROS_TYPE_INT64:
      out_type = FilterConstraint::INT64;
      out_int = *reinterpret_cast<const int64_t *>(base);
      return true;
    case rosidl_typesupport_introspection_c__ROS_TYPE_FLOAT: {
      float f = 0.0f;
      memcpy(&f, base, sizeof(f));
      out_type = FilterConstraint::DOUBLE;
      out_double = f;
      return true;
    }
    case rosidl_typesupport_introspection_c__ROS_TYPE_DOUBLE: {
      double d = 0.0;
      memcpy(&d, base, sizeof(d));
      out_type = FilterConstraint::DOUBLE;
      out_double = d;
      return true;
    }
    case rosidl_typesupport_introspection_c__ROS_TYPE_STRING: {
      const char *str = *reinterpret_cast<const char *const *>(base);
      out_type = FilterConstraint::STRING;
      out_str = str ? str : "";
      return true;
    }
    default:
      return false;
  }
}

/// Evaluate a single constraint against a ROS message.
/// Returns true if the message satisfies the constraint.
static inline bool
evaluate_constraint(const void *ros_message,
                    const rosidl_typesupport_introspection_c__MessageMembers *members,
                    const FilterConstraint &c) {
  // Find member by name
  for (uint32_t i = 0; i < members->member_count_; i++) {
    if (members->members_[i].name_ &&
        c.field_name == members->members_[i].name_) {
      FilterConstraint::ValueType field_type;
      int64_t field_int = 0;
      double field_double = 0.0;
      std::string field_str;
      if (!read_field_value(ros_message, members->members_[i],
                            field_type, field_int, field_double, field_str))
        return false;
      // Compare
      if (c.value_type == FilterConstraint::STRING ||
          field_type == FilterConstraint::STRING) {
        // String comparison
        int cmp = field_str.compare(c.str_val);
        switch (c.op) {
          case FilterOp::EQ: return cmp == 0;
          case FilterOp::NE: return cmp != 0;
          case FilterOp::LT: return cmp < 0;
          case FilterOp::GT: return cmp > 0;
          case FilterOp::LE: return cmp <= 0;
          case FilterOp::GE: return cmp >= 0;
        }
      } else if (c.value_type == FilterConstraint::DOUBLE ||
                 field_type == FilterConstraint::DOUBLE) {
        // Float comparison
        double fv = (field_type == FilterConstraint::DOUBLE) ? field_double : static_cast<double>(field_int);
        double cv = (c.value_type == FilterConstraint::DOUBLE) ? c.float_val : static_cast<double>(c.int_val);
        switch (c.op) {
          case FilterOp::EQ: return fv == cv;
          case FilterOp::NE: return fv != cv;
          case FilterOp::LT: return fv < cv;
          case FilterOp::GT: return fv > cv;
          case FilterOp::LE: return fv <= cv;
          case FilterOp::GE: return fv >= cv;
        }
      } else {
        // Integer comparison
        switch (c.op) {
          case FilterOp::EQ: return field_int == c.int_val;
          case FilterOp::NE: return field_int != c.int_val;
          case FilterOp::LT: return field_int < c.int_val;
          case FilterOp::GT: return field_int > c.int_val;
          case FilterOp::LE: return field_int <= c.int_val;
          case FilterOp::GE: return field_int >= c.int_val;
        }
      }
      return false; // unknown op
    }
  }
  // Field not found — constraint fails
  return false;
}

/// Evaluate a parsed filter expression against a deserialized ROS message.
/// Returns true if the message passes the filter (or no filter is set).
static inline bool
evaluate_filter(const void *ros_message,
                const rosidl_typesupport_introspection_c__MessageMembers *members,
                const std::vector<FilterConstraint> &constraints,
                bool conjunction_and) {
  if (constraints.empty()) return true;
  if (conjunction_and) {
    // All constraints must match
    for (const auto &c : constraints) {
      if (!evaluate_constraint(ros_message, members, c))
        return false;
    }
    return true;
  } else {
    // Any constraint must match
    for (const auto &c : constraints) {
      if (evaluate_constraint(ros_message, members, c))
        return true;
    }
    return false;
  }
}

#endif // RMW_AXON__INTERNAL_HPP_
