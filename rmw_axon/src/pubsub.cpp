#include "rmw_axon/internal.hpp"

rmw_publisher_t *rmw_create_publisher(
    const rmw_node_t *node, const rosidl_message_type_support_t *type_support,
    const char *topic_name, const rmw_qos_profile_t *qos_profile,
    const rmw_publisher_options_t *publisher_options) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(node, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(type_support, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(topic_name, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(qos_profile, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(publisher_options, NULL);

   int reliability =
       (qos_profile->reliability == RMW_QOS_POLICY_RELIABILITY_BEST_EFFORT) ? 0
                                                                            : 1;
   int durability =
       (qos_profile->durability == RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL)
           ? 1
           : 0;
   int history_kind =
       (qos_profile->history == RMW_QOS_POLICY_HISTORY_KEEP_ALL) ? 0 : 1;
   int depth = static_cast<int>(qos_profile->depth);
   if (history_kind != 0 && depth <= 0)
     depth = 10;
   axon_qos_duration_wire_t deadline =
       axon_qos_duration_to_wire(qos_profile->deadline);
   axon_qos_duration_wire_t lifespan =
       axon_qos_duration_to_wire(qos_profile->lifespan);
   int liveliness = axon_qos_liveliness_to_wire(qos_profile->liveliness);
   axon_qos_duration_wire_t liveliness_lease =
       axon_qos_duration_to_wire(qos_profile->liveliness_lease_duration);
   uint64_t sid = node->data ? ((axon_node_data_t *)node->data)->session_id : 0;

   if (sid == 0) {
     RMW_SET_ERROR_MSG("invalid session id in node");
     return NULL;
   }

   std::string type_name = get_message_type_name(type_support);

   axon_session_set_node_name(sid, node->name, node->namespace_);
   if (axon_session_create_publisher_with_qos(sid, topic_name, type_name.c_str(),
                                              reliability, durability,
                                              history_kind, depth,
                                              deadline.sec, deadline.nsec,
                                              lifespan.sec, lifespan.nsec,
                                              liveliness,
                                              liveliness_lease.sec, liveliness_lease.nsec) != 0) {
    RMW_SET_ERROR_MSG("axon_session_create_publisher failed");
    return NULL;
  }

  rmw_publisher_t *pub = rmw_publisher_allocate();
  if (!pub) {
    axon_session_destroy_publisher(sid, topic_name);
    RMW_SET_ERROR_MSG("failed to allocate publisher");
    return NULL;
  }

  axon_publisher_data_t *data =
      (axon_publisher_data_t *)rmw_allocate(sizeof(axon_publisher_data_t));
  if (!data) {
    axon_session_destroy_publisher(sid, topic_name);
    rmw_publisher_free(pub);
    RMW_SET_ERROR_MSG("failed to allocate publisher data");
    return NULL;
  }
  data->session_id = sid;
  data->topic_name = strdup(topic_name);
  data->topic_type = strdup(type_name.c_str());
  if (!data->topic_name || !data->topic_type) {
    if (data->topic_name)
      free(data->topic_name);
    if (data->topic_type)
      free(data->topic_type);
    rmw_free(data);
    rmw_publisher_free(pub);
    axon_session_destroy_publisher(sid, topic_name);
    RMW_SET_ERROR_MSG("failed to allocate topic strings");
    return NULL;
  }
  data->type_support = type_support;

  pub->implementation_identifier = "rmw_axon";
  pub->topic_name = data->topic_name;
  pub->data = data;
  pub->options = *publisher_options;
  // The core can loan serialized byte slots internally, but the ROS RMW loaned
  // message API requires a pointer to an initialized ros_message object.  Do
  // not advertise typed loaning until type-support construction and destruction
  // are implemented for those objects.
  pub->can_loan_messages = false;
  return pub;
}

rmw_ret_t rmw_destroy_publisher(rmw_node_t *node, rmw_publisher_t *publisher) {
  (void)node;
  if (publisher) {
    if (publisher->data) {
      axon_publisher_data_t *data = (axon_publisher_data_t *)publisher->data;
      axon_session_destroy_publisher(data->session_id, data->topic_name);
      if (data->topic_name)
        free(data->topic_name);
      if (data->topic_type)
        free(data->topic_type);
      rmw_free(data);
    }
    rmw_publisher_free(publisher);
  }
  return RMW_RET_OK;
}

rmw_subscription_t *rmw_create_subscription(
    const rmw_node_t *node, const rosidl_message_type_support_t *type_support,
    const char *topic_name, const rmw_qos_profile_t *qos_profile,
    const rmw_subscription_options_t *subscription_options) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(node, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(type_support, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(topic_name, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(qos_profile, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(subscription_options, NULL);

  int reliability =
      (qos_profile->reliability == RMW_QOS_POLICY_RELIABILITY_BEST_EFFORT) ? 0
                                                                           : 1;
  int durability =
      (qos_profile->durability == RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL)
          ? 1
          : 0;
   int history_kind =
       (qos_profile->history == RMW_QOS_POLICY_HISTORY_KEEP_ALL) ? 0 : 1;
   int depth = static_cast<int>(qos_profile->depth);
   if (history_kind != 0 && depth <= 0)
     depth = 10;
   axon_qos_duration_wire_t deadline =
       axon_qos_duration_to_wire(qos_profile->deadline);
   axon_qos_duration_wire_t lifespan =
       axon_qos_duration_to_wire(qos_profile->lifespan);
   int liveliness = axon_qos_liveliness_to_wire(qos_profile->liveliness);
   axon_qos_duration_wire_t liveliness_lease =
       axon_qos_duration_to_wire(qos_profile->liveliness_lease_duration);
   uint64_t sid = node->data ? ((axon_node_data_t *)node->data)->session_id : 0;

   if (sid == 0) {
     RMW_SET_ERROR_MSG("invalid session id in node");
     return NULL;
   }

   std::string type_name = get_message_type_name(type_support);

   uint64_t initial_seq = 0;
   axon_session_set_node_name(sid, node->name, node->namespace_);
   int64_t efd = axon_session_create_subscription_with_qos(
       sid, topic_name, type_name.c_str(), reliability, durability, history_kind,
       depth,
       deadline.sec, deadline.nsec,
       lifespan.sec, lifespan.nsec,
       liveliness,
       liveliness_lease.sec, liveliness_lease.nsec,
       &initial_seq);
  if (efd < 0) {
    RMW_SET_ERROR_MSG("axon_session_create_subscription failed");
    return NULL;
  }
  rmw_subscription_t *sub = rmw_subscription_allocate();
  if (!sub) {
    axon_session_destroy_subscription(sid, topic_name);
    RMW_SET_ERROR_MSG("failed to allocate subscription");
    return NULL;
  }

  axon_subscription_data_t *data = (axon_subscription_data_t *)rmw_allocate(
      sizeof(axon_subscription_data_t));
  if (!data) {
    axon_session_destroy_subscription(sid, topic_name);
    rmw_subscription_free(sub);
    RMW_SET_ERROR_MSG("failed to allocate subscription data");
    return NULL;
  }
  data->session_id = sid;
  data->topic_name = strdup(topic_name);
  data->topic_type = strdup(type_name.c_str());
  data->content_filter_expression = nullptr;
  if (!data->topic_name || !data->topic_type) {
    if (data->topic_name)
      free(data->topic_name);
    if (data->topic_type)
      free(data->topic_type);
    rmw_free(data);
    rmw_subscription_free(sub);
    axon_session_destroy_subscription(sid, topic_name);
    RMW_SET_ERROR_MSG("failed to allocate topic strings");
    return NULL;
  }
  data->next_seq = initial_seq;
  data->eventfd = (int)efd;
  data->type_support = type_support;
  axon_trace_fd_event("create", "subscription", data->eventfd,
                      data->topic_name);

  sub->implementation_identifier = "rmw_axon";
  sub->topic_name = data->topic_name;
  sub->data = data;
  sub->options = *subscription_options;
  sub->can_loan_messages = false;
  return sub;
}

rmw_ret_t rmw_destroy_subscription(rmw_node_t *node,
                                   rmw_subscription_t *subscription) {
  (void)node;
  if (subscription) {
    if (subscription->data) {
      axon_subscription_data_t *data =
          (axon_subscription_data_t *)subscription->data;
      axon_trace_fd_event("destroy", "subscription", data->eventfd,
                          data->topic_name);
      axon_session_destroy_subscription(data->session_id, data->topic_name);
      if (data->topic_name)
        free(data->topic_name);
      if (data->topic_type)
        free(data->topic_type);
      if (data->content_filter_expression)
        free(data->content_filter_expression);
      rmw_free(data);
    }
    rmw_subscription_free(subscription);
  }
  return RMW_RET_OK;
}

rmw_ret_t rmw_publish(const rmw_publisher_t *publisher, const void *ros_message,
                      rmw_publisher_allocation_t *allocation) {
  (void)allocation;
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(ros_message, RMW_RET_INVALID_ARGUMENT);

  axon_publisher_data_t *data = (axon_publisher_data_t *)publisher->data;

  const message_type_support_callbacks_t *callbacks =
      get_fastrtps_callbacks(data->type_support);
  if (!callbacks) {
    RMW_SET_ERROR_MSG("failed to get FastRTPS callbacks");
    return RMW_RET_ERROR;
  }

  size_t max_size = axon_serialized_size_for_message(callbacks, ros_message, 65536);
  size_t type_size = 0;
  if (axon_session_get_serialized_message_size(
          data->session_id, data->topic_type, &type_size) == 0 &&
      type_size > max_size) {
    max_size = type_size;
  }
  if (max_size < 65536) {
    max_size = 65536;
  }
  if (max_size > static_cast<size_t>(std::numeric_limits<uint32_t>::max()) - 128) {
    RMW_SET_ERROR_MSG("serialized message too large");
    return RMW_RET_ERROR;
  }

  uint32_t buffer_capacity = static_cast<uint32_t>(max_size + 128);
  uint8_t *buffer = (uint8_t *)malloc(buffer_capacity);
  if (!buffer) {
    RMW_SET_ERROR_MSG("failed to allocate serialization buffer");
    return RMW_RET_BAD_ALLOC;
  }

  bool serialized = false;
  uint32_t buffer_length = 0;
  for (int attempts = 0; attempts < 20; attempts++) {
    uint32_t attempt_len = buffer_capacity;
    if (serialize_message(callbacks, ros_message, buffer, &attempt_len)) {
      buffer_length = attempt_len;
      serialized = true;
      break;
    }

    if (!axon_grow_serialization_buffer(&buffer, &buffer_capacity,
                                        buffer_capacity + 1)) {
      free(buffer);
      RMW_SET_ERROR_MSG("failed to grow serialization buffer");
      return RMW_RET_BAD_ALLOC;
    }
  }
  if (!serialized) {
    free(buffer);
    RMW_SET_ERROR_MSG("CDR serialization failed");
    return RMW_RET_ERROR;
  }

  int64_t seq = axon_session_publish(data->session_id, data->topic_name, buffer,
                                     buffer_length);
  free(buffer);

  if (seq < 0) {
    RMW_SET_ERROR_MSG("axon_session_publish failed");
    return RMW_RET_ERROR;
  }

  AXON_TRACE_ROS("event=publish topic=%s bytes=%u seq=%ld", data->topic_name,
                 buffer_length, static_cast<long>(seq));

  return RMW_RET_OK;
}

rmw_ret_t rmw_publish_serialized_message(
    const rmw_publisher_t *publisher,
    const rmw_serialized_message_t *serialized_message,
    rmw_publisher_allocation_t *allocation) {
  (void)allocation;
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(publisher, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(serialized_message, RMW_RET_INVALID_ARGUMENT);

  axon_publisher_data_t *data = (axon_publisher_data_t *)publisher->data;

  int64_t seq = axon_session_publish(data->session_id, data->topic_name,
                                     serialized_message->buffer,
                                     serialized_message->buffer_length);

  if (seq < 0) {
    RMW_SET_ERROR_MSG("axon_session_publish failed");
    return RMW_RET_ERROR;
  }

  return RMW_RET_OK;
}

rmw_ret_t rmw_take(const rmw_subscription_t *subscription, void *ros_message,
                   bool *taken, rmw_subscription_allocation_t *allocation) {
  (void)allocation;
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(ros_message, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);

  axon_subscription_data_t *data =
      (axon_subscription_data_t *)subscription->data;
  *taken = false;

  const message_type_support_callbacks_t *callbacks =
      get_fastrtps_callbacks(data->type_support);
  if (!callbacks) {
    RMW_SET_ERROR_MSG("failed to get FastRTPS callbacks");
    return RMW_RET_ERROR;
  }

  // Parse content filter expression once per take sequence
  std::vector<FilterConstraint> filter_constraints;
  bool filter_conjunction_and = true;
  bool has_filter = false;
  const rosidl_typesupport_introspection_c__MessageMembers *filter_members = nullptr;
  if (data->content_filter_expression && data->content_filter_expression[0]) {
    filter_members = get_introspection_members(data->type_support);
    if (filter_members) {
      has_filter = parse_filter_expression(data->content_filter_expression,
                                           filter_constraints,
                                           filter_conjunction_and);
    }
  }

  // Pre-allocate receive buffer
  uint8_t small_buf[65536];
  size_t expected_size = sizeof(small_buf);
  size_t type_size = 0;
  if (axon_session_get_serialized_message_size(
          data->session_id, data->topic_type, &type_size) == 0 &&
      type_size > sizeof(small_buf)) {
    expected_size = type_size;
  }
  uint32_t out_len = static_cast<uint32_t>(expected_size);
  uint8_t *buf = (expected_size > sizeof(small_buf))
                     ? (uint8_t *)malloc(expected_size)
                     : small_buf;
  int needs_free = (buf != small_buf) ? 1 : 0;

  // Retry loop: take messages until one passes the content filter
  for (int attempts = 0; attempts < 1024; attempts++) {
    // Re-check data availability on each iteration
    if (axon_session_data_available(data->session_id, data->topic_name,
                                    data->next_seq) <= 0) {
      break;
    }

    int ret = -1;
    for (int resize_attempt = 0; resize_attempt < 8; ++resize_attempt) {
      out_len = static_cast<uint32_t>(expected_size);
      ret = axon_session_take_next(data->session_id, data->topic_name,
                                   &data->next_seq, buf, &out_len);
      if (ret == 0) {
        break;
      }
      if (out_len <= expected_size) {
        break;
      }

      if (needs_free)
        free(buf);
      expected_size = out_len;
      buf = (uint8_t *)malloc(expected_size);
      if (!buf) {
        RMW_SET_ERROR_MSG("failed to allocate receive buffer");
        return RMW_RET_BAD_ALLOC;
      }
      needs_free = 1;
    }
    if (ret != 0) {
      break; // no more data
    }

    // Deserialize
    if (!deserialize_message(callbacks, buf, out_len, ros_message)) {
      // Deserialization failed — skip this message
      continue;
    }

    // Evaluate content filter
    if (has_filter && filter_members) {
      if (!evaluate_filter(ros_message, filter_members,
                           filter_constraints, filter_conjunction_and)) {
        // Filter failed — try next message
        continue;
      }
    }

    // Message accepted
    *taken = true;
    AXON_TRACE_ROS("event=take topic=%s bytes=%u next_seq=%lu", data->topic_name,
                   out_len, static_cast<unsigned long>(data->next_seq));
    break;
  }

  if (needs_free)
    free(buf);
  return RMW_RET_OK; // No data is not an error
}

rmw_ret_t
rmw_take_serialized_message(const rmw_subscription_t *subscription,
                            rmw_serialized_message_t *serialized_message,
                            bool *taken,
                            rmw_subscription_allocation_t *allocation) {
  (void)allocation;
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(serialized_message, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);

  axon_subscription_data_t *data =
      (axon_subscription_data_t *)subscription->data;
  *taken = false;

  size_t expected_size = 65536;
  size_t type_size = 0;
  if (axon_session_get_serialized_message_size(
          data->session_id, data->topic_type, &type_size) == 0 &&
      type_size > expected_size) {
    expected_size = type_size;
  }

  // Re-check data availability — rmw_wait may return a spurious wakeup
  if (axon_session_data_available(data->session_id, data->topic_name,
                                  data->next_seq) <= 0) {
    return RMW_RET_OK;
  }

  rmw_ret_t r =
      axon_ensure_serialized_message_capacity(serialized_message, expected_size);
  if (r != RMW_RET_OK)
    return r;
  serialized_message->buffer_length = 0;

  int ret = -1;
  uint32_t actual_len = 0;
  for (int resize_attempt = 0; resize_attempt < 8; ++resize_attempt) {
    actual_len = static_cast<uint32_t>(expected_size);
    ret = axon_session_take_next(data->session_id, data->topic_name,
                                 &data->next_seq, serialized_message->buffer,
                                 &actual_len);
    if (ret == 0) {
      serialized_message->buffer_length = actual_len;
      *taken = true;
      return RMW_RET_OK;
    }
    if (actual_len <= expected_size) {
      break;
    }
    expected_size = actual_len;
    r = axon_ensure_serialized_message_capacity(serialized_message,
                                                expected_size);
    if (r != RMW_RET_OK)
      return r;
  }

  serialized_message->buffer_length = 0;
  return RMW_RET_OK;
}

rmw_ret_t rmw_take_with_info(const rmw_subscription_t *subscription,
                             void *ros_message, bool *taken,
                             rmw_message_info_t *message_info,
                             rmw_subscription_allocation_t *allocation) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(message_info, RMW_RET_INVALID_ARGUMENT);
  memset(message_info, 0, sizeof(*message_info));
  rmw_ret_t ret = rmw_take(subscription, ros_message, taken, allocation);
  if (ret == RMW_RET_OK && *taken) {
    auto now = std::chrono::system_clock::now();
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                  now.time_since_epoch())
                  .count();
    message_info->source_timestamp = ns;
    message_info->received_timestamp = ns;
    message_info->publisher_gid.implementation_identifier = "rmw_axon";
    axon_subscription_data_t *data =
        (axon_subscription_data_t *)subscription->data;
    axon_session_publisher_gid(data->session_id, data->topic_name,
                               message_info->publisher_gid.data);
  }
  return ret;
}

rmw_ret_t rmw_take_sequence(
    const rmw_subscription_t *subscription, size_t count,
    rmw_message_sequence_t *message_sequence,
    rmw_message_info_sequence_t *message_info_sequence, size_t *taken,
    rmw_subscription_allocation_t *allocation) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(subscription, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(message_sequence, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(message_info_sequence, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);

  if (count == 0 || message_sequence->capacity < count ||
      message_info_sequence->capacity < count || !message_sequence->data ||
      !message_info_sequence->data) {
    return RMW_RET_INVALID_ARGUMENT;
  }

  *taken = 0;
  message_sequence->size = 0;
  message_info_sequence->size = 0;

  for (size_t i = 0; i < count; ++i) {
    if (!message_sequence->data[i]) {
      return RMW_RET_INVALID_ARGUMENT;
    }

    bool one_taken = false;
    rmw_ret_t ret = rmw_take_with_info(subscription, message_sequence->data[i],
                                       &one_taken,
                                       &message_info_sequence->data[i],
                                       allocation);
    if (ret != RMW_RET_OK) {
      return ret;
    }
    if (!one_taken) {
      break;
    }

    ++(*taken);
    message_sequence->size = *taken;
    message_info_sequence->size = *taken;
  }

  return RMW_RET_OK;
}
