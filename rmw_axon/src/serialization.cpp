#include "rmw_axon/internal.hpp"

rmw_ret_t rmw_serialize(const void *ros_message,
                        const rosidl_message_type_support_t *type_support,
                        rmw_serialized_message_t *serialized_message) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(ros_message, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(type_support, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(serialized_message, RMW_RET_INVALID_ARGUMENT);

  const message_type_support_callbacks_t *callbacks =
      get_fastrtps_callbacks(type_support);
  if (!callbacks) {
    RMW_SET_ERROR_MSG("failed to get FastRTPS callbacks");
    return RMW_RET_ERROR;
  }

  size_t max_size =
      axon_serialized_size_for_message(callbacks, ros_message, 65536);
  if (max_size < 4096)
    max_size = 4096;
  if (max_size > static_cast<size_t>(std::numeric_limits<uint32_t>::max()) - 128) {
    RMW_SET_ERROR_MSG("serialized message too large");
    return RMW_RET_ERROR;
  }

  rmw_ret_t r =
      axon_ensure_serialized_message_capacity(serialized_message, max_size + 128);
  if (r != RMW_RET_OK)
    return r;
  serialized_message->buffer_length = 0;

  bool serialized = false;
  uint32_t buffer_length = 0;
  for (int attempts = 0; attempts < 20; attempts++) {
    uint32_t attempt_len =
        static_cast<uint32_t>(serialized_message->buffer_capacity);
    if (serialize_message(callbacks, ros_message, serialized_message->buffer,
                          &attempt_len)) {
      buffer_length = attempt_len;
      serialized = true;
      break;
    }

    size_t next_capacity = serialized_message->buffer_capacity * 2;
    if (next_capacity <= serialized_message->buffer_capacity ||
        next_capacity > std::numeric_limits<uint32_t>::max()) {
      RMW_SET_ERROR_MSG("serialized message too large");
      return RMW_RET_ERROR;
    }
    r = rmw_serialized_message_resize(serialized_message, next_capacity);
    if (r != RMW_RET_OK) {
      RMW_SET_ERROR_MSG("failed to grow serialized message buffer");
      return r;
    }
  }
  if (!serialized) {
    RMW_SET_ERROR_MSG("CDR serialization failed");
    return RMW_RET_ERROR;
  }
  serialized_message->buffer_length = buffer_length;
  return RMW_RET_OK;
}

rmw_ret_t rmw_deserialize(const rmw_serialized_message_t *serialized_message,
                          const rosidl_message_type_support_t *type_support,
                          void *ros_message) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(serialized_message, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(type_support, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(ros_message, RMW_RET_INVALID_ARGUMENT);

  const message_type_support_callbacks_t *callbacks =
      get_fastrtps_callbacks(type_support);
  if (!callbacks) {
    RMW_SET_ERROR_MSG("failed to get FastRTPS callbacks");
    return RMW_RET_ERROR;
  }

  if (!deserialize_message(callbacks, serialized_message->buffer,
                           serialized_message->buffer_length, ros_message)) {
    RMW_SET_ERROR_MSG("CDR deserialization failed");
    return RMW_RET_ERROR;
  }
  return RMW_RET_OK;
}

rmw_ret_t rmw_get_serialized_message_size(
    const rosidl_message_type_support_t *type_support,
    const rosidl_runtime_c__Sequence__bound *message_bounds, size_t *size) {
  if (!type_support || !size)
    return RMW_RET_INVALID_ARGUMENT;
  (void)message_bounds;
  const message_type_support_callbacks_t *callbacks =
      get_fastrtps_callbacks(type_support);
  if (!callbacks) {
    RMW_SET_ERROR_MSG("failed to get FastRTPS callbacks");
    return RMW_RET_ERROR;
  }
  char bounds_info = 0;
  *size = callbacks->max_serialized_size(bounds_info);
  return RMW_RET_OK;
}
