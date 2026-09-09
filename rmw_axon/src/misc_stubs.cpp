#include "rmw_axon/internal.hpp"

#include <cctype>
#include <cstring>
#include <string>
#include <vector>

#include "rmw/validate_full_topic_name.h"
#include "rmw/validate_namespace.h"
#include "rmw/validate_node_name.h"

#if __has_include("rcutils/sha256.h")
#include "rcutils/sha256.h"
#endif

rmw_ret_t rmw_validate_full_topic_name_with_size(
    const char *topic_name, size_t topic_name_length,
    int *validation_result, size_t *invalid_index);
rmw_ret_t rmw_validate_namespace_with_size(
    const char *namespace_, size_t namespace_length,
    int *validation_result, size_t *invalid_index);
rmw_ret_t rmw_validate_node_name_with_size(
    const char *node_name, size_t node_name_length,
    int *validation_result, size_t *invalid_index);

// ─── Name / namespace validation ───────────────────────────────────────────

static bool axon_is_name_char(char c) {
  unsigned char uc = static_cast<unsigned char>(c);
  return std::isalnum(uc) || c == '_';
}

static rmw_ret_t axon_validate_tokenized_name(
    const char *name, size_t length, bool require_absolute,
    bool allow_root_namespace, size_t max_length, int valid_code,
    int empty_code, int not_absolute_code, int ends_slash_code,
    int bad_char_code, int repeated_slash_code, int token_number_code,
    int too_long_code, int *validation_result, size_t *invalid_index) {
  if (!name || !validation_result)
    return RMW_RET_INVALID_ARGUMENT;

  *validation_result = valid_code;
  if (length == 0) {
    *validation_result = empty_code;
    if (invalid_index) *invalid_index = 0;
    return RMW_RET_OK;
  }

  if (require_absolute && name[0] != '/') {
    *validation_result = not_absolute_code;
    if (invalid_index) *invalid_index = 0;
    return RMW_RET_OK;
  }

  if (!allow_root_namespace && length == 1 && name[0] == '/') {
    *validation_result = ends_slash_code;
    if (invalid_index) *invalid_index = 0;
    return RMW_RET_OK;
  }

  if (!(allow_root_namespace && length == 1 && name[0] == '/') &&
      length > 1 && name[length - 1] == '/') {
    *validation_result = ends_slash_code;
    if (invalid_index) *invalid_index = length - 1;
    return RMW_RET_OK;
  }

  bool at_token_start = true;
  for (size_t i = 0; i < length; ++i) {
    char c = name[i];
    if (c == '/') {
      if (i > 0 && name[i - 1] == '/') {
        *validation_result = repeated_slash_code;
        if (invalid_index) *invalid_index = i;
        return RMW_RET_OK;
      }
      at_token_start = true;
      continue;
    }

    if (!axon_is_name_char(c)) {
      *validation_result = bad_char_code;
      if (invalid_index) *invalid_index = i;
      return RMW_RET_OK;
    }

    if (at_token_start && std::isdigit(static_cast<unsigned char>(c))) {
      *validation_result = token_number_code;
      if (invalid_index) *invalid_index = i;
      return RMW_RET_OK;
    }
    at_token_start = false;
  }

  if (length > max_length) {
    *validation_result = too_long_code;
    if (invalid_index) *invalid_index = max_length;
    return RMW_RET_OK;
  }

  return RMW_RET_OK;
}

rmw_ret_t rmw_validate_full_topic_name(const char *topic_name,
                                       int *validation_result,
                                       size_t *invalid_index) {
  if (!topic_name)
    return RMW_RET_INVALID_ARGUMENT;
  return rmw_validate_full_topic_name_with_size(
      topic_name, strlen(topic_name), validation_result, invalid_index);
}

rmw_ret_t rmw_validate_full_topic_name_with_size(const char *topic_name,
                                                 size_t topic_name_length,
                                                 int *validation_result,
                                                 size_t *invalid_index) {
  return axon_validate_tokenized_name(
      topic_name, topic_name_length, true, false, RMW_TOPIC_MAX_NAME_LENGTH,
      RMW_TOPIC_VALID, RMW_TOPIC_INVALID_IS_EMPTY_STRING,
      RMW_TOPIC_INVALID_NOT_ABSOLUTE,
      RMW_TOPIC_INVALID_ENDS_WITH_FORWARD_SLASH,
      RMW_TOPIC_INVALID_CONTAINS_UNALLOWED_CHARACTERS,
      RMW_TOPIC_INVALID_CONTAINS_REPEATED_FORWARD_SLASH,
      RMW_TOPIC_INVALID_NAME_TOKEN_STARTS_WITH_NUMBER,
      RMW_TOPIC_INVALID_TOO_LONG, validation_result, invalid_index);
}

const char *rmw_full_topic_name_validation_result_string(int validation_result) {
  switch (validation_result) {
  case RMW_TOPIC_VALID: return NULL;
  case RMW_TOPIC_INVALID_IS_EMPTY_STRING: return "topic name is empty";
  case RMW_TOPIC_INVALID_NOT_ABSOLUTE: return "topic name is not absolute";
  case RMW_TOPIC_INVALID_ENDS_WITH_FORWARD_SLASH: return "topic name ends with a forward slash";
  case RMW_TOPIC_INVALID_CONTAINS_UNALLOWED_CHARACTERS: return "topic name contains invalid characters";
  case RMW_TOPIC_INVALID_CONTAINS_REPEATED_FORWARD_SLASH: return "topic name contains repeated forward slashes";
  case RMW_TOPIC_INVALID_NAME_TOKEN_STARTS_WITH_NUMBER: return "topic name token starts with a number";
  case RMW_TOPIC_INVALID_TOO_LONG: return "topic name is too long";
  default: return "unknown topic name validation result";
  }
}

rmw_ret_t rmw_validate_namespace(const char *namespace_,
                                 int *validation_result,
                                 size_t *invalid_index) {
  if (!namespace_)
    return RMW_RET_INVALID_ARGUMENT;
  return rmw_validate_namespace_with_size(
      namespace_, strlen(namespace_), validation_result, invalid_index);
}

rmw_ret_t rmw_validate_namespace_with_size(const char *namespace_,
                                           size_t namespace_length,
                                           int *validation_result,
                                           size_t *invalid_index) {
  return axon_validate_tokenized_name(
      namespace_, namespace_length, true, true, RMW_NAMESPACE_MAX_LENGTH,
      RMW_NAMESPACE_VALID, RMW_NAMESPACE_INVALID_IS_EMPTY_STRING,
      RMW_NAMESPACE_INVALID_NOT_ABSOLUTE,
      RMW_NAMESPACE_INVALID_ENDS_WITH_FORWARD_SLASH,
      RMW_NAMESPACE_INVALID_CONTAINS_UNALLOWED_CHARACTERS,
      RMW_NAMESPACE_INVALID_CONTAINS_REPEATED_FORWARD_SLASH,
      RMW_NAMESPACE_INVALID_NAME_TOKEN_STARTS_WITH_NUMBER,
      RMW_NAMESPACE_INVALID_TOO_LONG, validation_result, invalid_index);
}

const char *rmw_namespace_validation_result_string(int validation_result) {
  switch (validation_result) {
  case RMW_NAMESPACE_VALID: return NULL;
  case RMW_NAMESPACE_INVALID_IS_EMPTY_STRING: return "namespace is empty";
  case RMW_NAMESPACE_INVALID_NOT_ABSOLUTE: return "namespace is not absolute";
  case RMW_NAMESPACE_INVALID_ENDS_WITH_FORWARD_SLASH: return "namespace ends with a forward slash";
  case RMW_NAMESPACE_INVALID_CONTAINS_UNALLOWED_CHARACTERS: return "namespace contains invalid characters";
  case RMW_NAMESPACE_INVALID_CONTAINS_REPEATED_FORWARD_SLASH: return "namespace contains repeated forward slashes";
  case RMW_NAMESPACE_INVALID_NAME_TOKEN_STARTS_WITH_NUMBER: return "namespace token starts with a number";
  case RMW_NAMESPACE_INVALID_TOO_LONG: return "namespace is too long";
  default: return "unknown namespace validation result";
  }
}

rmw_ret_t rmw_validate_node_name(const char *node_name,
                                 int *validation_result,
                                 size_t *invalid_index) {
  if (!node_name)
    return RMW_RET_INVALID_ARGUMENT;
  return rmw_validate_node_name_with_size(
      node_name, strlen(node_name), validation_result, invalid_index);
}

rmw_ret_t rmw_validate_node_name_with_size(const char *node_name,
                                           size_t node_name_length,
                                           int *validation_result,
                                           size_t *invalid_index) {
  if (!node_name || !validation_result)
    return RMW_RET_INVALID_ARGUMENT;
  *validation_result = RMW_NODE_NAME_VALID;
  if (node_name_length == 0) {
    *validation_result = RMW_NODE_NAME_INVALID_IS_EMPTY_STRING;
    if (invalid_index) *invalid_index = 0;
    return RMW_RET_OK;
  }
  for (size_t i = 0; i < node_name_length; ++i) {
    char c = node_name[i];
    if (!axon_is_name_char(c)) {
      *validation_result = RMW_NODE_NAME_INVALID_CONTAINS_UNALLOWED_CHARACTERS;
      if (invalid_index) *invalid_index = i;
      return RMW_RET_OK;
    }
    if (i == 0 && std::isdigit(static_cast<unsigned char>(c))) {
      *validation_result = RMW_NODE_NAME_INVALID_STARTS_WITH_NUMBER;
      if (invalid_index) *invalid_index = i;
      return RMW_RET_OK;
    }
  }
  if (node_name_length > RMW_NODE_NAME_MAX_NAME_LENGTH) {
    *validation_result = RMW_NODE_NAME_INVALID_TOO_LONG;
    if (invalid_index) *invalid_index = RMW_NODE_NAME_MAX_NAME_LENGTH;
  }
  return RMW_RET_OK;
}

const char *rmw_node_name_validation_result_string(int validation_result) {
  switch (validation_result) {
  case RMW_NODE_NAME_VALID: return NULL;
  case RMW_NODE_NAME_INVALID_IS_EMPTY_STRING: return "node name is empty";
  case RMW_NODE_NAME_INVALID_CONTAINS_UNALLOWED_CHARACTERS: return "node name contains invalid characters";
  case RMW_NODE_NAME_INVALID_STARTS_WITH_NUMBER: return "node name starts with a number";
  case RMW_NODE_NAME_INVALID_TOO_LONG: return "node name is too long";
  default: return "unknown node name validation result";
  }
}

// ─── GID ────────────────────────────────────────────────────────────────────

rmw_ret_t rmw_get_gid_for_publisher(const rmw_publisher_t *publisher,
                                    rmw_gid_t *gid) {
  if (!publisher || !publisher->data || !gid)
    return RMW_RET_INVALID_ARGUMENT;
  memset(gid, 0, sizeof(rmw_gid_t));
  gid->implementation_identifier = "rmw_axon";
  axon_publisher_data_t *data =
      static_cast<axon_publisher_data_t *>(publisher->data);
  if (axon_session_publisher_gid(data->session_id, data->topic_name,
                                 gid->data) != 0)
    return RMW_RET_ERROR;
  return RMW_RET_OK;
}

rmw_ret_t rmw_compare_gids_equal(const rmw_gid_t *gid1, const rmw_gid_t *gid2,
                                 bool *result) {
  if (!gid1 || !gid2 || !result)
    return RMW_RET_INVALID_ARGUMENT;
  *result = (memcmp(gid1->data, gid2->data, RMW_GID_STORAGE_SIZE) == 0);
  return RMW_RET_OK;
}

rmw_ret_t rmw_get_gid_for_client(const rmw_client_t *client, rmw_gid_t *gid) {
  if (!client || !client->data || !gid)
    return RMW_RET_INVALID_ARGUMENT;
  memset(gid, 0, sizeof(rmw_gid_t));
  gid->implementation_identifier = "rmw_axon";
  axon_client_data_t *data = static_cast<axon_client_data_t *>(client->data);
  memcpy(gid->data, data->client_gid, sizeof(data->client_gid));
  return RMW_RET_OK;
}

// ─── Allocation helpers ─────────────────────────────────────────────────────

rmw_ret_t rmw_init_publisher_allocation(
    const rosidl_message_type_support_t *type_support,
    const rosidl_runtime_c__Sequence__bound *message_bounds,
    rmw_publisher_allocation_t *allocation) {
  (void)type_support;
  (void)message_bounds;
  (void)allocation;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_fini_publisher_allocation(rmw_publisher_allocation_t *allocation) {
  (void)allocation;
  return RMW_RET_OK;
}

rmw_ret_t rmw_init_subscription_allocation(
    const rosidl_message_type_support_t *type_support,
    const rosidl_runtime_c__Sequence__bound *message_bounds,
    rmw_subscription_allocation_t *allocation) {
  (void)type_support;
  (void)message_bounds;
  (void)allocation;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_fini_subscription_allocation(rmw_subscription_allocation_t *allocation) {
  (void)allocation;
  return RMW_RET_OK;
}

// ─── Counting helpers ───────────────────────────────────────────────────────

rmw_ret_t rmw_count_publishers(const rmw_node_t *node, const char *topic_name,
                               size_t *count) {
  if (!node || !topic_name || !count)
    return RMW_RET_INVALID_ARGUMENT;
  uint64_t sid = node->data ? ((axon_node_data_t *)node->data)->session_id : 0;
  uint32_t c = 0;
  if (axon_session_count_publishers(sid, topic_name, &c) != 0)
    return RMW_RET_ERROR;
  *count = c;
  return RMW_RET_OK;
}

rmw_ret_t rmw_count_subscribers(const rmw_node_t *node, const char *topic_name,
                                size_t *count) {
  if (!node || !topic_name || !count)
    return RMW_RET_INVALID_ARGUMENT;
  uint64_t sid = node->data ? ((axon_node_data_t *)node->data)->session_id : 0;
  uint32_t c = 0;
  if (axon_session_count_subscribers(sid, topic_name, &c) != 0)
    return RMW_RET_ERROR;
  *count = c;
  return RMW_RET_OK;
}

rmw_ret_t rmw_count_clients(const rmw_node_t *node, const char *service_name,
                            size_t *count) {
  if (!node || !service_name || !count)
    return RMW_RET_INVALID_ARGUMENT;
  uint64_t sid = node->data ? ((axon_node_data_t *)node->data)->session_id : 0;
  uint32_t c = 0;
  if (axon_session_count_clients(sid, service_name, &c) != 0)
    return RMW_RET_ERROR;
  *count = c;
  return RMW_RET_OK;
}

rmw_ret_t rmw_count_services(const rmw_node_t *node, const char *service_name,
                             size_t *count) {
  if (!node || !service_name || !count)
    return RMW_RET_INVALID_ARGUMENT;
  uint64_t sid = node->data ? ((axon_node_data_t *)node->data)->session_id : 0;
  uint32_t c = 0;
  if (axon_session_count_services(sid, service_name, &c) != 0)
    return RMW_RET_ERROR;
  *count = c;
  return RMW_RET_OK;
}

// ─── Misc ───────────────────────────────────────────────────────────────────

const char *rmw_get_implementation_identifier(void) { return "rmw_axon"; }

rmw_ret_t rmw_set_log_severity(rmw_log_severity_t severity) {
  (void)severity;
  return RMW_RET_OK;
}

rmw_ret_t rmw_publisher_assert_liveliness(const rmw_publisher_t *publisher) {
  if (!publisher)
    return RMW_RET_INVALID_ARGUMENT;
  axon_publisher_data_t *data = (axon_publisher_data_t *)publisher->data;
  if (axon_session_assert_liveliness(data->session_id) != 0)
    return RMW_RET_ERROR;
  return RMW_RET_OK;
}

rmw_ret_t rmw_node_assert_liveliness(const rmw_node_t *node) {
  if (!node)
    return RMW_RET_INVALID_ARGUMENT;
  axon_node_data_t *data = (axon_node_data_t *)node->data;
  if (axon_session_assert_liveliness(data->session_id) != 0)
    return RMW_RET_ERROR;
  return RMW_RET_OK;
}

rmw_ret_t rmw_publisher_wait_for_all_acked(const rmw_publisher_t *publisher,
                                           rmw_time_t wait_timeout) {
  (void)publisher;
  (void)wait_timeout;
  return RMW_RET_OK;
}

// ─── Matched counts and actual QoS ──────────────────────────────────────────

static void
fill_qos_profile(rmw_qos_profile_t *qos,
                 int32_t rel, int32_t dur, int32_t history, size_t depth,
                 int32_t liveliness,
                 uint64_t ll_s, uint32_t ll_ns,
                 uint64_t dl_s, uint32_t dl_ns,
                 uint64_t ls_s, uint32_t ls_ns) {
  qos->reliability = rel ? RMW_QOS_POLICY_RELIABILITY_RELIABLE
                         : RMW_QOS_POLICY_RELIABILITY_BEST_EFFORT;
  qos->durability = dur ? RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL
                        : RMW_QOS_POLICY_DURABILITY_VOLATILE;
  qos->history = history == 0 ? RMW_QOS_POLICY_HISTORY_KEEP_ALL
                              : RMW_QOS_POLICY_HISTORY_KEEP_LAST;
  qos->depth = depth;
  if (liveliness == 1)
    qos->liveliness = RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_TOPIC;
  else if (liveliness == 2)
    qos->liveliness = RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_PARTICIPANT;
  else
    qos->liveliness = RMW_QOS_POLICY_LIVELINESS_AUTOMATIC;
  if (ll_s == 0 && ll_ns == 0) {
    qos->liveliness_lease_duration = RMW_DURATION_INFINITE;
  } else {
    qos->liveliness_lease_duration.sec = (int64_t)ll_s;
    qos->liveliness_lease_duration.nsec = (uint32_t)ll_ns;
  }
  if (dl_s == 0 && dl_ns == 0) {
    qos->deadline = RMW_DURATION_INFINITE;
  } else {
    qos->deadline.sec = (int64_t)dl_s;
    qos->deadline.nsec = (uint32_t)dl_ns;
  }
  if (ls_s == 0 && ls_ns == 0) {
    qos->lifespan = RMW_DURATION_INFINITE;
  } else {
    qos->lifespan.sec = (int64_t)ls_s;
    qos->lifespan.nsec = (uint32_t)ls_ns;
  }
  qos->avoid_ros_namespace_conventions = false;
}

rmw_ret_t
rmw_publisher_count_matched_subscriptions(const rmw_publisher_t *publisher,
                                          size_t *subscription_count) {
  if (!publisher || !subscription_count)
    return RMW_RET_INVALID_ARGUMENT;
  axon_publisher_data_t *data = (axon_publisher_data_t *)publisher->data;
  uint32_t c = 0;
  if (axon_session_count_matched_subs(data->session_id, data->topic_name, &c) !=
      0)
    return RMW_RET_ERROR;
  *subscription_count = c;
  return RMW_RET_OK;
}

rmw_ret_t rmw_publisher_get_actual_qos(const rmw_publisher_t *publisher,
                                        rmw_qos_profile_t *qos) {
  if (!publisher || !qos)
    return RMW_RET_INVALID_ARGUMENT;
  axon_publisher_data_t *data = (axon_publisher_data_t *)publisher->data;
  uint64_t sid = data->session_id;
  int32_t rel = 0, dur = 0, history = 1, liveliness = 0;
  size_t depth = 0;
  uint64_t ll_s = 0, dl_s = 0, ls_s = 0;
  uint32_t ll_ns = 0, dl_ns = 0, ls_ns = 0;
  if (axon_session_publisher_actual_qos_full(
          sid, data->topic_name, &rel, &dur, &history, &depth,
          &liveliness, &ll_s, &ll_ns, &dl_s, &dl_ns, &ls_s, &ls_ns) != 0)
    return RMW_RET_ERROR;
  fill_qos_profile(qos, rel, dur, history, depth, liveliness,
                   ll_s, ll_ns, dl_s, dl_ns, ls_s, ls_ns);
  return RMW_RET_OK;
}

rmw_ret_t rmw_subscription_count_matched_publishers(
    const rmw_subscription_t *subscription, size_t *publisher_count) {
  if (!subscription || !publisher_count)
    return RMW_RET_INVALID_ARGUMENT;
  axon_subscription_data_t *data =
      (axon_subscription_data_t *)subscription->data;
  uint32_t c = 0;
  if (axon_session_count_matched_pubs(data->session_id, data->topic_name, &c) !=
      0)
    return RMW_RET_ERROR;
  *publisher_count = c;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_subscription_get_actual_qos(const rmw_subscription_t *subscription,
                                rmw_qos_profile_t *qos) {
  if (!subscription || !qos)
    return RMW_RET_INVALID_ARGUMENT;
  axon_subscription_data_t *data =
      (axon_subscription_data_t *)subscription->data;
  uint64_t sid = data->session_id;
  int32_t rel = 0, dur = 0, history = 1, liveliness = 0;
  size_t depth = 0;
  uint64_t ll_s = 0, dl_s = 0, ls_s = 0;
  uint32_t ll_ns = 0, dl_ns = 0, ls_ns = 0;
  if (axon_session_subscription_actual_qos_full(
          sid, data->topic_name, &rel, &dur, &history, &depth,
          &liveliness, &ll_s, &ll_ns, &dl_s, &dl_ns, &ls_s, &ls_ns) != 0)
    return RMW_RET_ERROR;
  fill_qos_profile(qos, rel, dur, history, depth, liveliness,
                   ll_s, ll_ns, dl_s, dl_ns, ls_s, ls_ns);
  return RMW_RET_OK;
}

// ─── Loaned message bridge ──────────────────────────────────────────────────

rmw_ret_t
rmw_borrow_loaned_message(const rmw_publisher_t *publisher,
                          const rosidl_message_type_support_t *type_support,
                          void **ros_message) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(type_support, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(ros_message, RMW_RET_INVALID_ARGUMENT);

  axon_publisher_data_t *data = (axon_publisher_data_t *)publisher->data;
  const message_type_support_callbacks_t *callbacks =
      get_fastrtps_callbacks(type_support);
  char bounds_info = 0;
  size_t max_size = callbacks ? callbacks->max_serialized_size(bounds_info) : 0;
  if (max_size == 0) {
    size_t type_size = 0;
    if (axon_session_get_serialized_message_size(
            data->session_id, data->topic_type, &type_size) == 0 &&
        type_size > 0) {
      max_size = type_size;
    } else {
      max_size = 8 * 1024 * 1024;
    }
  }

  uint8_t *ptr =
      axon_session_borrow_loaned(data->session_id, data->topic_name, max_size);
  if (!ptr) {
    RMW_SET_ERROR_MSG("axon_session_borrow_loaned returned null");
    return RMW_RET_ERROR;
  }

  *ros_message = ptr;
  return RMW_RET_OK;
}

rmw_ret_t rmw_publish_loaned_message(const rmw_publisher_t *publisher,
                                     void *ros_message,
                                     rmw_publisher_allocation_t *allocation) {
  (void)allocation;
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(ros_message, RMW_RET_INVALID_ARGUMENT);

  axon_publisher_data_t *data = (axon_publisher_data_t *)publisher->data;
  const message_type_support_callbacks_t *callbacks =
      get_fastrtps_callbacks(data->type_support);
  char bounds_info = 0;
  size_t max_size =
      callbacks ? callbacks->max_serialized_size(bounds_info) : 4096;
  if (max_size == 0)
    max_size = 4096;

  if (axon_session_publish_loaned(data->session_id, data->topic_name,
                                  static_cast<uint8_t *>(ros_message),
                                  max_size) != 0) {
    RMW_SET_ERROR_MSG("axon_session_publish_loaned failed");
    return RMW_RET_ERROR;
  }
  return RMW_RET_OK;
}

rmw_ret_t
rmw_return_loaned_message_from_publisher(const rmw_publisher_t *publisher,
                                         void *loaned_message) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(loaned_message, RMW_RET_INVALID_ARGUMENT);

  axon_publisher_data_t *data = (axon_publisher_data_t *)publisher->data;
  const message_type_support_callbacks_t *callbacks =
      get_fastrtps_callbacks(data->type_support);
  char bounds_info = 0;
  size_t max_size =
      callbacks ? callbacks->max_serialized_size(bounds_info) : 4096;
  if (max_size == 0)
    max_size = 4096;

  axon_session_return_loaned(data->session_id, data->topic_name,
                             static_cast<uint8_t *>(loaned_message), max_size);
  return RMW_RET_OK;
}

rmw_ret_t rmw_take_loaned_message(const rmw_subscription_t *subscription,
                                  void **loaned_message, bool *taken,
                                  rmw_subscription_allocation_t *allocation) {
  (void)allocation;
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(loaned_message, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);

  axon_subscription_data_t *data =
      (axon_subscription_data_t *)subscription->data;
  *taken = false;

  size_t size_out = 0;
  const uint8_t *ptr = axon_session_take_loaned(
      data->session_id, data->topic_name, data->next_seq, &size_out);
  if (!ptr)
    return RMW_RET_OK;

  *loaned_message = const_cast<uint8_t *>(ptr);
  *taken = true;
  data->next_seq++;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_take_loaned_message_with_info(const rmw_subscription_t *subscription,
                                  void **loaned_message, bool *taken,
                                  rmw_message_info_t *message_info,
                                  rmw_subscription_allocation_t *allocation) {
  (void)allocation;
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(loaned_message, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(message_info, RMW_RET_INVALID_ARGUMENT);

  axon_subscription_data_t *data =
      (axon_subscription_data_t *)subscription->data;
  *taken = false;

  size_t size_out = 0;
  const uint8_t *ptr = axon_session_take_loaned(
      data->session_id, data->topic_name, data->next_seq, &size_out);
  if (!ptr)
    return RMW_RET_OK;

  *loaned_message = const_cast<uint8_t *>(ptr);
  *taken = true;

  auto now = std::chrono::system_clock::now();
  auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                now.time_since_epoch())
                .count();
  message_info->source_timestamp = ns;
  message_info->received_timestamp = ns;
  data->next_seq++;
  return RMW_RET_OK;
}

rmw_ret_t rmw_return_loaned_message_from_subscription(
    const rmw_subscription_t *subscription, void *loaned_message) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(loaned_message, RMW_RET_INVALID_ARGUMENT);

  axon_subscription_data_t *data =
      (axon_subscription_data_t *)subscription->data;
  const message_type_support_callbacks_t *callbacks =
      get_fastrtps_callbacks(data->type_support);
  char bounds_info = 0;
  size_t max_size =
      callbacks ? callbacks->max_serialized_size(bounds_info) : 4096;
  if (max_size == 0)
    max_size = 4096;

  axon_session_return_loaned(data->session_id, data->topic_name,
                             static_cast<uint8_t *>(loaned_message), max_size);
  return RMW_RET_OK;
}

// ─── Take serialized message with info ──────────────────────────────────────

rmw_ret_t rmw_take_serialized_message_with_info(
    const rmw_subscription_t *subscription,
    rmw_serialized_message_t *serialized_message, bool *taken,
    rmw_message_info_t *message_info,
    rmw_subscription_allocation_t *allocation) {
  if (!subscription || !serialized_message || !taken || !message_info)
    return RMW_RET_INVALID_ARGUMENT;
  (void)allocation;
  axon_subscription_data_t *data =
      (axon_subscription_data_t *)subscription->data;
  *taken = false;
  memset(message_info, 0, sizeof(*message_info));

  if (axon_session_data_available(data->session_id, data->topic_name,
                                  data->next_seq) <= 0) {
    return RMW_RET_OK;
  }

  size_t expected_size = 65536;
  size_t type_size = 0;
  if (axon_session_get_serialized_message_size(
          data->session_id, data->topic_type, &type_size) == 0 &&
      type_size > expected_size) {
    expected_size = type_size;
  }
  rmw_ret_t r =
      axon_ensure_serialized_message_capacity(serialized_message, expected_size);
  if (r != RMW_RET_OK)
    return r;
  serialized_message->buffer_length = 0;

  uint32_t out_len = 0;
  int64_t source_ts = 0, recv_ts = 0, seq_num = 0;
  int32_t ret = -1;
  for (int resize_attempt = 0; resize_attempt < 8; ++resize_attempt) {
    out_len = static_cast<uint32_t>(serialized_message->buffer_capacity);
    ret = axon_session_take_serialized_message_with_info_next(
        data->session_id, data->topic_name, &data->next_seq,
        serialized_message->buffer, &out_len, &source_ts, &recv_ts, &seq_num);
    if (ret == 0) {
      break;
    }
    if (out_len <= serialized_message->buffer_capacity) {
      break;
    }
    r = axon_ensure_serialized_message_capacity(serialized_message, out_len);
    if (r != RMW_RET_OK) {
      *taken = false;
      return r;
    }
  }

  if (ret != 0) {
    *taken = false;
    serialized_message->buffer_length = 0;
    return RMW_RET_OK;
  }
  *taken = true;
  serialized_message->buffer_length = out_len;
  message_info->source_timestamp = source_ts;
  message_info->received_timestamp = recv_ts;
  message_info->publication_sequence_number = static_cast<uint64_t>(seq_num);
  message_info->reception_sequence_number = static_cast<uint64_t>(seq_num);
  message_info->publisher_gid.implementation_identifier = "rmw_axon";
  axon_session_publisher_gid(data->session_id, data->topic_name,
                             message_info->publisher_gid.data);
  message_info->from_intra_process = false;
  return RMW_RET_OK;
}

// ─── Take event ─────────────────────────────────────────────────────────────

rmw_ret_t rmw_take_event(const rmw_event_t *event_handle, void *event_info,
                         bool *taken) {
  if (!event_handle || !event_handle->data || !event_info || !taken)
    return RMW_RET_INVALID_ARGUMENT;
  *taken = false;
  axon_event_data_t *ev = (axon_event_data_t *)event_handle->data;
  int64_t count = 0, timestamp = 0, alive_count = 0, not_alive_count = 0;
  int32_t ret = axon_session_take_event(ev->session_id, ev->event_handle,
                                        &count, &timestamp,
                                        &alive_count, &not_alive_count);
  if (ret != 0)
    return RMW_RET_OK;
  *taken = true;
  int64_t count_change = count - ev->last_count;
  int64_t alive_change = alive_count - ev->last_alive_count;
  int64_t not_alive_change = not_alive_count - ev->last_not_alive_count;
  ev->last_count = count;
  ev->last_alive_count = alive_count;
  ev->last_not_alive_count = not_alive_count;
  switch (event_handle->event_type) {
  case RMW_EVENT_LIVELINESS_LOST: {
    rmw_liveliness_lost_status_t *st =
        (rmw_liveliness_lost_status_t *)event_info;
    st->total_count = count;
    st->total_count_change = count_change;
    break;
  }
  case RMW_EVENT_LIVELINESS_CHANGED: {
    rmw_liveliness_changed_status_t *st =
        (rmw_liveliness_changed_status_t *)event_info;
    st->alive_count = alive_count;
    st->not_alive_count = not_alive_count;
    st->alive_count_change = alive_change;
    st->not_alive_count_change = not_alive_change;
    break;
  }
  case RMW_EVENT_REQUESTED_DEADLINE_MISSED:
  case RMW_EVENT_OFFERED_DEADLINE_MISSED: {
    rmw_requested_deadline_missed_status_t *st =
        (rmw_requested_deadline_missed_status_t *)event_info;
    st->total_count = count;
    st->total_count_change = count_change;
    break;
  }
  case RMW_EVENT_MESSAGE_LOST: {
    rmw_message_lost_status_t *st = (rmw_message_lost_status_t *)event_info;
    st->total_count = count;
    st->total_count_change = count_change;
    break;
  }
  default:
    break;
  }
  return RMW_RET_OK;
}

// ─── Query stubs ────────────────────────────────────────────────────────────

using names_and_types_query_fn = int (*)(uint64_t, const char*, const char*, size_t*, char***, char***);

static bool axon_next_c_string(const uint8_t *&p, const uint8_t *end,
                               const char *&value, size_t &len) {
  if (p >= end)
    return false;
  const void *nul = memchr(p, 0, static_cast<size_t>(end - p));
  if (!nul)
    return false;
  value = reinterpret_cast<const char *>(p);
  len = static_cast<const uint8_t *>(nul) - p;
  p = static_cast<const uint8_t *>(nul) + 1;
  return true;
}

static rmw_ret_t axon_fini_endpoint_info_and_return(
    rmw_topic_endpoint_info_array_t *info_array, rcutils_allocator_t *allocator,
    rmw_ret_t ret) {
  rmw_ret_t fini_ret = rmw_topic_endpoint_info_array_fini(info_array, allocator);
  (void)fini_ret;
  return ret;
}

static rmw_ret_t
names_and_types_by_node_impl(const rmw_node_t *node, rcutils_allocator_t *allocator,
                             const char *node_name, const char *node_namespace,
                             rmw_names_and_types_t *out,
                             names_and_types_query_fn query_fn) {
  if (!node || !allocator || !node_name || !out)
    return RMW_RET_INVALID_ARGUMENT;
  uint64_t sid = node->data ? ((axon_node_data_t *)node->data)->session_id : 0;
  char **names = nullptr;
  char **types = nullptr;
  size_t count = 0;
  if (query_fn(sid, node_name, node_namespace, &count, &names, &types) != 0)
    return RMW_RET_ERROR;
  if (count == 0) {
    out->names.size = 0;
    out->names.data = NULL;
    out->types = NULL;
    for (size_t i = 0; i < count; i++) {
      free(names[i]);
      free(types[i]);
    }
    free(names);
    free(types);
    return RMW_RET_OK;
  }
  rmw_ret_t r =
      rmw_names_and_types_init(out, count, allocator);
  if (r != RMW_RET_OK) {
    for (size_t i = 0; i < count; i++) {
      free(names[i]);
      free(types[i]);
    }
    free(names);
    free(types);
    return RMW_RET_BAD_ALLOC;
  }
  for (size_t i = 0; i < count; i++) {
    out->names.data[i] = strndup(names[i], strlen(names[i]));
    if (!out->names.data[i]) {
      rmw_ret_t _ret = rmw_names_and_types_fini(out);
      (void)_ret;
      for (size_t j = 0; j < count; j++) {
        free(names[j]);
        free(types[j]);
      }
      free(names);
      free(types);
      return RMW_RET_BAD_ALLOC;
    }
    if (rcutils_string_array_init(&out->types[i], 1,
                                  allocator) != RCUTILS_RET_OK) {
      rmw_ret_t _ret = rmw_names_and_types_fini(out);
      (void)_ret;
      for (size_t j = 0; j < count; j++) {
        free(names[j]);
        free(types[j]);
      }
      free(names);
      free(types);
      return RMW_RET_BAD_ALLOC;
    }
    out->types[i].data[0] =
        strndup(types[i], strlen(types[i]));
    if (!out->types[i].data[0]) {
      rmw_ret_t _ret = rmw_names_and_types_fini(out);
      (void)_ret;
      for (size_t j = 0; j < count; j++) {
        free(names[j]);
        free(types[j]);
      }
      free(names);
      free(types);
      return RMW_RET_BAD_ALLOC;
    }
  }
  for (size_t i = 0; i < count; i++) {
    free(names[i]);
    free(types[i]);
  }
  free(names);
  free(types);
  return RMW_RET_OK;
}

rmw_ret_t rmw_get_publisher_names_and_types_by_node(
    const rmw_node_t *node, rcutils_allocator_t *allocator,
    const char *node_name, const char *node_namespace, bool no_demangle,
    rmw_names_and_types_t *topic_names_and_types) {
  (void)no_demangle;
  return names_and_types_by_node_impl(node, allocator, node_name, node_namespace,
                                       topic_names_and_types, axon_session_get_publishers_by_node);
}

rmw_ret_t rmw_get_subscriber_names_and_types_by_node(
    const rmw_node_t *node, rcutils_allocator_t *allocator,
    const char *node_name, const char *node_namespace, bool no_demangle,
    rmw_names_and_types_t *topic_names_and_types) {
  (void)no_demangle;
  return names_and_types_by_node_impl(node, allocator, node_name, node_namespace,
                                       topic_names_and_types, axon_session_get_subscribers_by_node);
}

rmw_ret_t rmw_get_service_names_and_types_by_node(
    const rmw_node_t *node, rcutils_allocator_t *allocator,
    const char *node_name, const char *node_namespace,
    rmw_names_and_types_t *service_names_and_types) {
  return names_and_types_by_node_impl(node, allocator, node_name, node_namespace,
                                       service_names_and_types, axon_session_get_services_by_node);
}

rmw_ret_t rmw_get_client_names_and_types_by_node(
    const rmw_node_t *node, rcutils_allocator_t *allocator,
    const char *node_name, const char *node_namespace,
    rmw_names_and_types_t *service_names_and_types) {
  return names_and_types_by_node_impl(node, allocator, node_name, node_namespace,
                                       service_names_and_types, axon_session_get_clients_by_node);
}

static rmw_ret_t fill_endpoint_info(uint64_t sid, const char *topic_name,
                                    rcutils_allocator_t *allocator,
                                    rmw_topic_endpoint_info_array_t *info_array,
                                    rmw_endpoint_type_t endpoint_type) {
  uint32_t count = 0;
  std::vector<uint8_t> buf;
  size_t capacity = 65536;
  constexpr size_t kMaxEndpointInfoBuffer = 16 * 1024 * 1024;
  int ret = -1;
  while (capacity <= kMaxEndpointInfoBuffer) {
    buf.assign(capacity, 0);
    count = 0;
    if (endpoint_type == RMW_ENDPOINT_PUBLISHER) {
      ret = axon_session_get_publishers_info(
          sid, topic_name, &count, buf.data(), static_cast<uint32_t>(buf.size()));
    } else {
      ret = axon_session_get_subscriptions_info(
          sid, topic_name, &count, buf.data(), static_cast<uint32_t>(buf.size()));
    }
    if (ret == 0 || ret != -2)
      break;
    capacity *= 2;
  }
  if (ret != 0)
    return RMW_RET_ERROR;
  if (count == 0) {
    info_array->size = 0;
    info_array->info_array = nullptr;
    return RMW_RET_OK;
  }
  rmw_ret_t init_ret =
      rmw_topic_endpoint_info_array_init_with_size(info_array, count, allocator);
  if (init_ret != RMW_RET_OK)
    return init_ret;

  const uint8_t *p = buf.data();
  const uint8_t *end = buf.data() + buf.size();
  for (uint32_t i = 0; i < count; i++) {
    auto *info = &info_array->info_array[i];
    const char *node_name = nullptr;
    const char *node_namespace = nullptr;
    const char *topic_type = nullptr;
    size_t ignored_len = 0;
    size_t topic_type_len = 0;
    if (!axon_next_c_string(p, end, node_name, ignored_len) ||
        !axon_next_c_string(p, end, node_namespace, ignored_len) ||
        !axon_next_c_string(p, end, topic_type, topic_type_len)) {
      return axon_fini_endpoint_info_and_return(info_array, allocator,
                                                RMW_RET_ERROR);
    }
    if (rmw_topic_endpoint_info_set_node_name(info, node_name, allocator) !=
        RMW_RET_OK) {
      return axon_fini_endpoint_info_and_return(info_array, allocator,
                                                RMW_RET_BAD_ALLOC);
    }
    if (rmw_topic_endpoint_info_set_node_namespace(info, node_namespace,
                                                   allocator) != RMW_RET_OK) {
      return axon_fini_endpoint_info_and_return(info_array, allocator,
                                                RMW_RET_BAD_ALLOC);
    }
    if (rmw_topic_endpoint_info_set_topic_type(info, topic_type, allocator) !=
        RMW_RET_OK) {
      return axon_fini_endpoint_info_and_return(info_array, allocator,
                                                RMW_RET_BAD_ALLOC);
    }
    if (p + 16 + (4 * 5) + (12 * 3) > end) {
      return axon_fini_endpoint_info_and_return(info_array, allocator,
                                                RMW_RET_ERROR);
    }
    if (rmw_topic_endpoint_info_set_gid(info, p, 16) != RMW_RET_OK) {
      return axon_fini_endpoint_info_and_return(info_array, allocator,
                                                RMW_RET_BAD_ALLOC);
    }
    p += 16;
    int32_t rel, dur, hist, depth;
    memcpy(&rel, p, sizeof(rel));
    p += sizeof(rel);
    memcpy(&dur, p, sizeof(dur));
    p += sizeof(dur);
    memcpy(&hist, p, sizeof(hist));
    p += sizeof(hist);
    memcpy(&depth, p, sizeof(depth));
    p += sizeof(depth);
    info->endpoint_type = endpoint_type;
    info->qos_profile.reliability =
        rel ? RMW_QOS_POLICY_RELIABILITY_RELIABLE
            : RMW_QOS_POLICY_RELIABILITY_BEST_EFFORT;
    info->qos_profile.durability =
        dur ? RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL
            : RMW_QOS_POLICY_DURABILITY_VOLATILE;
    info->qos_profile.history = hist == 0 ? RMW_QOS_POLICY_HISTORY_KEEP_ALL
                                          : RMW_QOS_POLICY_HISTORY_KEEP_LAST;
    info->qos_profile.depth = depth;
    (void)hist;
    (void)depth;
#if __has_include("rcutils/sha256.h")
    rosidl_type_hash_t type_hash = rosidl_get_zero_initialized_type_hash();
    type_hash.version = 1;
    rcutils_sha256_ctx_t sha_ctx;
    rcutils_sha256_init(&sha_ctx);
    rcutils_sha256_update(&sha_ctx, (const uint8_t *)topic_type,
                          topic_type_len);
    rcutils_sha256_final(&sha_ctx, type_hash.value);
    if (rmw_topic_endpoint_info_set_topic_type_hash(info, &type_hash) !=
        RMW_RET_OK) {
    }
#endif
    // liveliness
    int32_t liveliness_val;
    memcpy(&liveliness_val, p, sizeof(liveliness_val));
    p += sizeof(liveliness_val);
    if (liveliness_val == 1)
      info->qos_profile.liveliness = RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_TOPIC;
    else if (liveliness_val == 2)
      info->qos_profile.liveliness = RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_PARTICIPANT;
    else
      info->qos_profile.liveliness = RMW_QOS_POLICY_LIVELINESS_AUTOMATIC;
    // liveliness_lease_duration
    uint64_t ll_s;
    uint32_t ll_ns;
    memcpy(&ll_s, p, sizeof(ll_s));
    p += sizeof(ll_s);
    memcpy(&ll_ns, p, sizeof(ll_ns));
    p += sizeof(ll_ns);
    if (ll_s == 0 && ll_ns == 0) {
      info->qos_profile.liveliness_lease_duration = RMW_DURATION_INFINITE;
    } else {
      info->qos_profile.liveliness_lease_duration.sec = (int64_t)ll_s;
      info->qos_profile.liveliness_lease_duration.nsec = (uint32_t)ll_ns;
    }
    // deadline
    uint64_t dl_s;
    uint32_t dl_ns;
    memcpy(&dl_s, p, sizeof(dl_s));
    p += sizeof(dl_s);
    memcpy(&dl_ns, p, sizeof(dl_ns));
    p += sizeof(dl_ns);
    if (dl_s == 0 && dl_ns == 0) {
      info->qos_profile.deadline = RMW_DURATION_INFINITE;
    } else {
      info->qos_profile.deadline.sec = (int64_t)dl_s;
      info->qos_profile.deadline.nsec = (uint32_t)dl_ns;
    }
    // lifespan
    uint64_t ls_s;
    uint32_t ls_ns;
    memcpy(&ls_s, p, sizeof(ls_s));
    p += sizeof(ls_s);
    memcpy(&ls_ns, p, sizeof(ls_ns));
    p += sizeof(ls_ns);
    if (ls_s == 0 && ls_ns == 0) {
      info->qos_profile.lifespan = RMW_DURATION_INFINITE;
    } else {
      info->qos_profile.lifespan.sec = (int64_t)ls_s;
      info->qos_profile.lifespan.nsec = (uint32_t)ls_ns;
    }
    info->qos_profile.avoid_ros_namespace_conventions = false;
  }
  return RMW_RET_OK;
}

rmw_ret_t rmw_get_subscriptions_info_by_topic(
    const rmw_node_t *node, rcutils_allocator_t *allocator,
    const char *topic_name, bool no_mangle,
    rmw_topic_endpoint_info_array_t *subscriptions_info) {
  if (!node || !allocator || !topic_name || !subscriptions_info)
    return RMW_RET_INVALID_ARGUMENT;
  (void)no_mangle;
  uint64_t sid = node->data ? ((axon_node_data_t *)node->data)->session_id : 0;
  return fill_endpoint_info(sid, topic_name, allocator, subscriptions_info,
                            RMW_ENDPOINT_SUBSCRIPTION);
}

rmw_ret_t rmw_get_publishers_info_by_topic(
    const rmw_node_t *node, rcutils_allocator_t *allocator,
    const char *topic_name, bool no_mangle,
    rmw_topic_endpoint_info_array_t *publishers_info) {
  if (!node || !allocator || !topic_name || !publishers_info)
    return RMW_RET_INVALID_ARGUMENT;
  (void)no_mangle;
  uint64_t sid = node->data ? ((axon_node_data_t *)node->data)->session_id : 0;
  return fill_endpoint_info(sid, topic_name, allocator, publishers_info,
                            RMW_ENDPOINT_PUBLISHER);
}

// ─── QoS compatibility and service QoS stubs ────────────────────────────────

rmw_ret_t
rmw_qos_profile_check_compatible(const rmw_qos_profile_t publisher_profile,
                                  const rmw_qos_profile_t subscription_profile,
                                  rmw_qos_compatibility_type_t *compatibility,
                                  char *reason, size_t reason_size) {
  if (reason && reason_size > 0) reason[0] = '\0';

  if (publisher_profile.reliability == RMW_QOS_POLICY_RELIABILITY_BEST_EFFORT &&
      subscription_profile.reliability == RMW_QOS_POLICY_RELIABILITY_RELIABLE) {
    *compatibility = RMW_QOS_COMPATIBILITY_ERROR;
    snprintf(reason, reason_size, "BEST_EFFORT publisher incompatible with RELIABLE subscriber");
    return RMW_RET_OK;
  }

  if (subscription_profile.durability == RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL &&
      publisher_profile.durability == RMW_QOS_POLICY_DURABILITY_VOLATILE) {
    *compatibility = RMW_QOS_COMPATIBILITY_ERROR;
    snprintf(reason, reason_size, "TRANSIENT_LOCAL subscriber incompatible with VOLATILE publisher");
    return RMW_RET_OK;
  }

  uint64_t pub_deadline_ns =
      axon_qos_duration_total_ns_or_zero(publisher_profile.deadline);
  uint64_t sub_deadline_ns =
      axon_qos_duration_total_ns_or_zero(subscription_profile.deadline);
  if (pub_deadline_ns > 0 && sub_deadline_ns > 0 &&
      pub_deadline_ns > sub_deadline_ns) {
    *compatibility = RMW_QOS_COMPATIBILITY_ERROR;
    snprintf(reason, reason_size, "publisher deadline > subscriber deadline");
    return RMW_RET_OK;
  }

  if (subscription_profile.liveliness == RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_TOPIC &&
      publisher_profile.liveliness == RMW_QOS_POLICY_LIVELINESS_AUTOMATIC) {
    *compatibility = RMW_QOS_COMPATIBILITY_ERROR;
    snprintf(reason, reason_size, "MANUAL_BY_TOPIC subscriber incompatible with AUTOMATIC publisher");
    return RMW_RET_OK;
  }
  if (subscription_profile.liveliness == RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_PARTICIPANT &&
      publisher_profile.liveliness != RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_PARTICIPANT) {
    *compatibility = RMW_QOS_COMPATIBILITY_ERROR;
    snprintf(reason, reason_size, "MANUAL_BY_PARTICIPANT subscriber requires MANUAL_BY_PARTICIPANT publisher");
    return RMW_RET_OK;
  }

  uint64_t pub_lifespan_ns =
      axon_qos_duration_total_ns_or_zero(publisher_profile.lifespan);
  uint64_t sub_lifespan_ns =
      axon_qos_duration_total_ns_or_zero(subscription_profile.lifespan);
  if (pub_lifespan_ns > 0 && sub_lifespan_ns > 0 &&
      pub_lifespan_ns < sub_lifespan_ns) {
    *compatibility = RMW_QOS_COMPATIBILITY_ERROR;
    snprintf(reason, reason_size, "publisher lifespan < subscriber lifespan");
    return RMW_RET_OK;
  }

  *compatibility = RMW_QOS_COMPATIBILITY_OK;
  return RMW_RET_OK;
}

static rmw_ret_t service_qos_getter(uint64_t sid, const char *name, int role,
                                     rmw_qos_profile_t *qos) {
  int32_t rel = 0, dur = 0, history = 1, liveliness = 0;
  size_t depth = 0;
  uint64_t ll_s = 0, dl_s = 0, ls_s = 0;
  uint32_t ll_ns = 0, dl_ns = 0, ls_ns = 0;
  if (axon_session_service_qos(sid, name, role,
      &rel, &dur, &history, &depth, &liveliness,
      &ll_s, &ll_ns, &dl_s, &dl_ns, &ls_s, &ls_ns) != 0)
    return RMW_RET_ERROR;
  qos->reliability = rel ? RMW_QOS_POLICY_RELIABILITY_RELIABLE
                         : RMW_QOS_POLICY_RELIABILITY_BEST_EFFORT;
  qos->durability = dur ? RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL
                        : RMW_QOS_POLICY_DURABILITY_VOLATILE;
  qos->history = history == 0 ? RMW_QOS_POLICY_HISTORY_KEEP_ALL
                              : RMW_QOS_POLICY_HISTORY_KEEP_LAST;
  qos->depth = depth;
  qos->liveliness = liveliness == 1 ? RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_TOPIC
                    : liveliness == 2 ? RMW_QOS_POLICY_LIVELINESS_MANUAL_BY_PARTICIPANT
                    : RMW_QOS_POLICY_LIVELINESS_AUTOMATIC;
  if (ll_s == 0 && ll_ns == 0) qos->liveliness_lease_duration = RMW_DURATION_INFINITE;
  else { qos->liveliness_lease_duration.sec = (int64_t)ll_s; qos->liveliness_lease_duration.nsec = (uint32_t)ll_ns; }
  if (dl_s == 0 && dl_ns == 0) qos->deadline = RMW_DURATION_INFINITE;
  else { qos->deadline.sec = (int64_t)dl_s; qos->deadline.nsec = (uint32_t)dl_ns; }
  if (ls_s == 0 && ls_ns == 0) qos->lifespan = RMW_DURATION_INFINITE;
  else { qos->lifespan.sec = (int64_t)ls_s; qos->lifespan.nsec = (uint32_t)ls_ns; }
  qos->avoid_ros_namespace_conventions = false;
  return RMW_RET_OK;
}

rmw_ret_t rmw_service_response_publisher_get_actual_qos(const rmw_service_t *s, rmw_qos_profile_t *q) {
  if (!s || !q) return RMW_RET_INVALID_ARGUMENT;
  auto *d = (axon_service_data_t *)s->data;
  return service_qos_getter(d->session_id, d->service_name, 1, q);
}
rmw_ret_t rmw_service_request_subscription_get_actual_qos(const rmw_service_t *s, rmw_qos_profile_t *q) {
  if (!s || !q) return RMW_RET_INVALID_ARGUMENT;
  auto *d = (axon_service_data_t *)s->data;
  return service_qos_getter(d->session_id, d->service_name, 0, q);
}
rmw_ret_t rmw_client_request_publisher_get_actual_qos(const rmw_client_t *c, rmw_qos_profile_t *q) {
  if (!c || !q) return RMW_RET_INVALID_ARGUMENT;
  auto *d = (axon_client_data_t *)c->data;
  return service_qos_getter(d->session_id, d->service_name, 2, q);
}
rmw_ret_t rmw_client_response_subscription_get_actual_qos(const rmw_client_t *c, rmw_qos_profile_t *q) {
  if (!c || !q) return RMW_RET_INVALID_ARGUMENT;
  auto *d = (axon_client_data_t *)c->data;
  return service_qos_getter(d->session_id, d->service_name, 3, q);
}

// ─── Callback stubs ─────────────────────────────────────────────────────────

rmw_ret_t rmw_service_set_on_new_request_callback(rmw_service_t *service,
                                                  rmw_event_callback_t callback,
                                                  const void *user_data) {
  (void)service;
  (void)callback;
  (void)user_data;
  return RMW_RET_OK;
}

rmw_ret_t rmw_client_set_on_new_response_callback(rmw_client_t *client,
                                                  rmw_event_callback_t callback,
                                                  const void *user_data) {
  (void)client;
  (void)callback;
  (void)user_data;
  return RMW_RET_OK;
}

rmw_ret_t
rmw_subscription_set_on_new_message_callback(rmw_subscription_t *subscription,
                                             rmw_event_callback_t callback,
                                             const void *user_data) {
  (void)subscription;
  (void)callback;
  (void)user_data;
  return RMW_RET_OK;
}

// ─── Network flow endpoints ─────────────────────────────────────────────────

using flow_endpoints_query_fn = int (*)(uint64_t, const char*, size_t*, char***);

static rmw_ret_t
network_flow_endpoints_impl(uint64_t sid, const char *topic_name,
                             rcutils_allocator_t *allocator,
                             rmw_network_flow_endpoint_array_t *arr,
                             flow_endpoints_query_fn query_fn) {
  char **addrs = nullptr;
  size_t count = 0;
  if (query_fn(sid, topic_name, &count, &addrs) != 0)
    return RMW_RET_ERROR;

  arr->size = count;
  arr->network_flow_endpoint = nullptr;
  arr->allocator = allocator;
  if (count > 0) {
    arr->network_flow_endpoint =
        static_cast<rmw_network_flow_endpoint_t *>(allocator->allocate(
            count * sizeof(rmw_network_flow_endpoint_t), allocator->state));
    if (!arr->network_flow_endpoint) {
      if (addrs) {
        for (size_t i = 0; i < count; i++)
          free(addrs[i]);
        free(addrs);
      }
      arr->size = 0;
      return RMW_RET_BAD_ALLOC;
    }

    for (size_t i = 0; i < count; i++) {
      rmw_network_flow_endpoint_t endpoint =
          rmw_get_zero_initialized_network_flow_endpoint();
      endpoint.transport_protocol = RMW_TRANSPORT_PROTOCOL_UDP;
      endpoint.internet_protocol = RMW_INTERNET_PROTOCOL_IPV4;

      const char *addr = addrs && addrs[i] ? addrs[i] : "";
      const char *colon = strrchr(addr, ':');
      if (colon && colon != addr) {
        std::string host(addr, static_cast<size_t>(colon - addr));
        long port = strtol(colon + 1, nullptr, 10);
        if (port > 0 && port <= 65535) {
          endpoint.transport_port = static_cast<uint16_t>(port);
        }
        if (!host.empty()) {
          rmw_ret_t set_ret = rmw_network_flow_endpoint_set_internet_address(
              &endpoint, host.c_str(), host.size());
          if (set_ret != RMW_RET_OK) {
            strncpy(endpoint.internet_address, host.c_str(),
                    RMW_INET_ADDRSTRLEN - 1);
            endpoint.internet_address[RMW_INET_ADDRSTRLEN - 1] = '\0';
          }
        }
      }
      arr->network_flow_endpoint[i] = endpoint;
    }
  }

  if (addrs) {
    for (size_t i = 0; i < count; i++)
      free(addrs[i]);
    free(addrs);
  }
  return RMW_RET_OK;
}

rmw_ret_t rmw_publisher_get_network_flow_endpoints(
    const rmw_publisher_t *publisher, rcutils_allocator_t *allocator,
    rmw_network_flow_endpoint_array_t *network_flow_endpoint_array) {
  if (!publisher || !allocator || !network_flow_endpoint_array)
    return RMW_RET_INVALID_ARGUMENT;
  axon_publisher_data_t *data = (axon_publisher_data_t *)publisher->data;
  return network_flow_endpoints_impl(data->session_id, data->topic_name,
                                      allocator, network_flow_endpoint_array,
                                      axon_session_publisher_flow_endpoints);
}

rmw_ret_t rmw_subscription_get_network_flow_endpoints(
    const rmw_subscription_t *subscription, rcutils_allocator_t *allocator,
    rmw_network_flow_endpoint_array_t *network_flow_endpoint_array) {
  if (!subscription || !allocator || !network_flow_endpoint_array)
    return RMW_RET_INVALID_ARGUMENT;
  axon_subscription_data_t *data =
      (axon_subscription_data_t *)subscription->data;
  return network_flow_endpoints_impl(data->session_id, data->topic_name,
                                      allocator, network_flow_endpoint_array,
                                      axon_session_subscription_flow_endpoints);
}

// ─── Dynamic message stubs (Jazzy-only APIs) ────────────────────────────────

#if __has_include("rmw/dynamic_message_type_support.h")
rmw_ret_t rmw_take_dynamic_message(
    const rmw_subscription_t *subscription,
    rosidl_dynamic_typesupport_dynamic_data_t *dynamic_message, bool *taken,
    rmw_subscription_allocation_t *allocation) {
  (void)subscription;
  (void)dynamic_message;
  (void)taken;
  (void)allocation;
  return RMW_RET_UNSUPPORTED;
}

rmw_ret_t rmw_take_dynamic_message_with_info(
    const rmw_subscription_t *subscription,
    rosidl_dynamic_typesupport_dynamic_data_t *dynamic_message, bool *taken,
    rmw_message_info_t *message_info,
    rmw_subscription_allocation_t *allocation) {
  (void)subscription;
  (void)dynamic_message;
  (void)taken;
  (void)message_info;
  (void)allocation;
  return RMW_RET_UNSUPPORTED;
}

rmw_ret_t rmw_serialization_support_init(
    const char *serialization_lib_name, rcutils_allocator_t *allocator,
    rosidl_dynamic_typesupport_serialization_support_t *serialization_support) {
  (void)serialization_lib_name;
  (void)allocator;
  (void)serialization_support;
  return RMW_RET_UNSUPPORTED;
}
#endif
