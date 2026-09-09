#include "rmw_axon/internal.hpp"

namespace {
std::atomic<uint64_t> g_client_gid_counter{1};

void axon_make_client_gid(uint64_t session_id, const char *service_name,
                         uint8_t out[16]) {
  const uint64_t counter =
      g_client_gid_counter.fetch_add(1, std::memory_order_relaxed);
  // Session handles restart from one in every process. Include the PID so
  // clients in different ROS processes cannot accidentally share a GID.
  const uint64_t process_session =
      (static_cast<uint64_t>(::getpid()) << 32) ^ session_id;
  uint64_t hash = 1469598103934665603ULL ^ process_session;
  if (service_name) {
    for (const unsigned char *p =
             reinterpret_cast<const unsigned char *>(service_name);
         *p != '\0'; ++p) {
      hash ^= *p;
      hash *= 1099511628211ULL;
    }
  }
  hash ^= counter + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
  memcpy(out, &counter, sizeof(counter));
  memcpy(out + sizeof(counter), &hash, sizeof(hash));
}
} // namespace

rmw_service_t *rmw_create_service(
    const rmw_node_t *node, const rosidl_service_type_support_t *type_support,
    const char *service_name, const rmw_qos_profile_t *qos_profile) {
  (void)node;
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(type_support, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(service_name, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(qos_profile, NULL);

  int reliability =
      (qos_profile->reliability == RMW_QOS_POLICY_RELIABILITY_BEST_EFFORT) ? 0
                                                                           : 1;
  int durability =
      (qos_profile->durability == RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL) ? 1
                                                                             : 0;
  int history_kind =
      (qos_profile->history == RMW_QOS_POLICY_HISTORY_KEEP_ALL) ? 0 : 1;
  int32_t depth = static_cast<int32_t>(qos_profile->depth);
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

  std::string type_name = get_service_type_name(type_support);
  if (axon_session_create_service_with_qos(
          sid, service_name, type_name.c_str(),
          reliability, durability, history_kind, depth,
          deadline.sec, deadline.nsec, lifespan.sec, lifespan.nsec,
          liveliness, liveliness_lease.sec, liveliness_lease.nsec) != 0) {
    RMW_SET_ERROR_MSG("axon_session_create_service failed");
    return NULL;
  }

  rmw_service_t *svc = rmw_service_allocate();
  if (!svc) {
    axon_session_destroy_service(sid, service_name);
    RMW_SET_ERROR_MSG("failed to allocate service");
    return NULL;
  }

  axon_service_data_t *data =
      (axon_service_data_t *)rmw_allocate(sizeof(axon_service_data_t));
  if (!data) {
    axon_session_destroy_service(sid, service_name);
    rmw_service_free(svc);
    RMW_SET_ERROR_MSG("failed to allocate service data");
    return NULL;
  }
  data->session_id = sid;
  data->service_name = strdup(service_name);
  if (!data->service_name) {
    rmw_free(data);
    rmw_service_free(svc);
    axon_session_destroy_service(sid, service_name);
    RMW_SET_ERROR_MSG("failed to allocate service name");
    return NULL;
  }
  data->next_seq = static_cast<uint64_t>(
      axon_session_service_initial_seq(sid, service_name));
  data->type_support = type_support;

  int64_t req_efd = axon_session_service_request_eventfd(sid, service_name);
  if (req_efd < 0) {
    RMW_SET_ERROR_MSG("failed to get service request eventfd");
    free(data->service_name);
    rmw_free(data);
    rmw_service_free(svc);
    axon_session_destroy_service(sid, service_name);
    return NULL;
  }
  data->request_eventfd = (int)req_efd;
  axon_trace_fd_event("create", "service", data->request_eventfd,
                      data->service_name);

  svc->implementation_identifier = "rmw_axon";
  svc->service_name = data->service_name;
  svc->data = data;
  return svc;
}

rmw_ret_t rmw_destroy_service(rmw_node_t *node, rmw_service_t *service) {
  (void)node;
  if (service) {
    if (service->data) {
      axon_service_data_t *data = (axon_service_data_t *)service->data;
      axon_trace_fd_event("destroy", "service", data->request_eventfd,
                          data->service_name);
      axon_session_destroy_service(data->session_id, data->service_name);
      if (data->service_name)
        free(data->service_name);
      rmw_free(data);
    }
    rmw_service_free(service);
  }
  return RMW_RET_OK;
}

rmw_ret_t rmw_take_request(const rmw_service_t *service,
                           rmw_service_info_t *request_header,
                           void *ros_request, bool *taken) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(service, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(request_header, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(ros_request, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);

  axon_service_data_t *data = (axon_service_data_t *)service->data;
  *taken = false;

  const message_type_support_callbacks_t *callbacks =
      get_service_msg_callbacks(data->type_support, true);
  if (!callbacks) {
    RMW_SET_ERROR_MSG("failed to get request callbacks");
    return RMW_RET_ERROR;
  }

  uint8_t small_buf[65536];
  uint32_t buf_capacity = sizeof(small_buf);
  uint8_t *buf = small_buf;
  int needs_free = 0;

  // Retry up to 2 times: handle buffer-too-small and slot-overwritten
  for (int attempt = 0; attempt < 2; attempt++) {
    uint32_t out_len = buf_capacity;
    uint8_t client_gid[16] = {0};
    int64_t request_sequence = static_cast<int64_t>(data->next_seq);
    int ret = axon_session_take_request_with_info(
        data->session_id, data->service_name, data->next_seq, buf, &out_len,
        client_gid, &request_sequence);

    if (ret == 0) {
      memset(request_header, 0, sizeof(*request_header));
      memcpy(request_header->request_id.writer_guid, client_gid,
             sizeof(request_header->request_id.writer_guid));
      request_header->request_id.sequence_number = request_sequence;
      data->next_seq++;
      if (!deserialize_message(callbacks, buf, out_len, ros_request)) {
        RMW_SET_ERROR_MSG("CDR deserialize request failed");
        *taken = false;
        if (needs_free) free(buf);
        return RMW_RET_ERROR;
      }
      *taken = true;
      AXON_TRACE_ROS("event=service_request service=%s bytes=%u request_seq=%ld",
                     data->service_name, out_len,
                     static_cast<long>(request_sequence));
      if (needs_free) free(buf);
      return RMW_RET_OK;
    }

    if (ret == -2) {
      // Buffer too small — allocate required size and retry
      uint32_t required = out_len;
      uint8_t *new_buf = (uint8_t *)malloc(required);
      if (!new_buf) {
        if (needs_free) free(buf);
        RMW_SET_ERROR_MSG("failed to allocate take_request buffer");
        return RMW_RET_BAD_ALLOC;
      }
      if (needs_free) free(buf);
      buf = new_buf;
      buf_capacity = required;
      needs_free = 1;
      continue;
    }

    if (ret == -3) {
      // The writer advanced write_index but has not published the slot length
      // yet. Keep next_seq unchanged so the request is not skipped.
      break;
    }

    // ret < 0 (not -2) — slot overwritten or other error
    // Check if write index has advanced past next_seq and skip ahead
    uint64_t current = (uint64_t)axon_session_service_initial_seq(
        data->session_id, data->service_name);
    if (current > data->next_seq) {
      data->next_seq = current;
      continue; // retry at new seq
    }
    break; // can't recover
  }

  if (needs_free) free(buf);
  return RMW_RET_OK;
}

rmw_ret_t rmw_send_response(const rmw_service_t *service,
                            rmw_request_id_t *request_id, void *ros_response) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(service, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(request_id, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(ros_response, RMW_RET_INVALID_ARGUMENT);

  axon_service_data_t *data = (axon_service_data_t *)service->data;

  const message_type_support_callbacks_t *callbacks =
      get_service_msg_callbacks(data->type_support, false);
  if (!callbacks) {
    RMW_SET_ERROR_MSG("failed to get response callbacks");
    return RMW_RET_ERROR;
  }

  size_t max_size =
      axon_serialized_size_for_message(callbacks, ros_response, 4096);
  if (max_size < 4096)
    max_size = 4096;
  if (max_size > static_cast<size_t>(std::numeric_limits<uint32_t>::max()) - 128) {
    RMW_SET_ERROR_MSG("serialized response too large");
    return RMW_RET_ERROR;
  }

  uint32_t buffer_capacity = static_cast<uint32_t>(max_size + 128);
  uint8_t *buffer = (uint8_t *)malloc(buffer_capacity);
  if (!buffer) {
    RMW_SET_ERROR_MSG("failed to allocate response buffer");
    return RMW_RET_BAD_ALLOC;
  }

  bool serialized = false;
  uint32_t buffer_length = 0;
  for (int attempts = 0; attempts < 20; attempts++) {
    uint32_t attempt_len = buffer_capacity;
    if (serialize_message(callbacks, ros_response, buffer, &attempt_len)) {
      buffer_length = attempt_len;
      serialized = true;
      break;
    }

    if (!axon_grow_serialization_buffer(&buffer, &buffer_capacity,
                                        buffer_capacity + 1)) {
      free(buffer);
      RMW_SET_ERROR_MSG("failed to grow response buffer");
      return RMW_RET_BAD_ALLOC;
    }
  }
  if (!serialized) {
    free(buffer);
    RMW_SET_ERROR_MSG("CDR response serialization failed");
    return RMW_RET_ERROR;
  }

  int64_t seq = axon_session_send_response_with_info(
      data->session_id, data->service_name,
      reinterpret_cast<const uint8_t *>(request_id->writer_guid),
      request_id->sequence_number, buffer, buffer_length);
  free(buffer);

  if (seq < 0) {
    RMW_SET_ERROR_MSG("axon_session_send_response failed");
    return RMW_RET_ERROR;
  }

  AXON_TRACE_ROS("event=service_response service=%s bytes=%u seq=%ld",
                 data->service_name, buffer_length, static_cast<long>(seq));

  return RMW_RET_OK;
}

rmw_client_t *rmw_create_client(
    const rmw_node_t *node, const rosidl_service_type_support_t *type_support,
    const char *service_name, const rmw_qos_profile_t *qos_profile) {
  (void)node;
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(type_support, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(service_name, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(qos_profile, NULL);

  int reliability =
      (qos_profile->reliability == RMW_QOS_POLICY_RELIABILITY_BEST_EFFORT) ? 0
                                                                           : 1;
  int durability =
      (qos_profile->durability == RMW_QOS_POLICY_DURABILITY_TRANSIENT_LOCAL) ? 1
                                                                             : 0;
  int history_kind =
      (qos_profile->history == RMW_QOS_POLICY_HISTORY_KEEP_ALL) ? 0 : 1;
  int32_t depth = static_cast<int32_t>(qos_profile->depth);
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
  std::string type_name = get_service_type_name(type_support);
  if (axon_session_create_client_with_qos(
          sid, service_name, type_name.c_str(),
          reliability, durability, history_kind, depth,
          deadline.sec, deadline.nsec, lifespan.sec, lifespan.nsec,
          liveliness, liveliness_lease.sec, liveliness_lease.nsec) != 0) {
    RMW_SET_ERROR_MSG("axon_session_create_client failed");
    return NULL;
  }

  rmw_client_t *client = rmw_client_allocate();
  if (!client) {
    axon_session_destroy_client(sid, service_name);
    RMW_SET_ERROR_MSG("failed to allocate client");
    return NULL;
  }

  axon_client_data_t *data =
      (axon_client_data_t *)rmw_allocate(sizeof(axon_client_data_t));
  if (!data) {
    axon_session_destroy_client(sid, service_name);
    rmw_client_free(client);
    RMW_SET_ERROR_MSG("failed to allocate client data");
    return NULL;
  }
  data->session_id = sid;
  data->service_name = strdup(service_name);
  if (!data->service_name) {
    rmw_free(data);
    rmw_client_free(client);
    axon_session_destroy_client(sid, service_name);
    RMW_SET_ERROR_MSG("failed to allocate service name");
    return NULL;
  }
  data->next_seq = static_cast<uint64_t>(
      axon_session_client_initial_seq(sid, service_name));
  data->type_support = type_support;
  axon_make_client_gid(sid, service_name, data->client_gid);

  int64_t res_efd = axon_session_service_response_eventfd(sid, service_name);
  if (res_efd < 0) {
    RMW_SET_ERROR_MSG("failed to get client response eventfd");
    free(data->service_name);
    rmw_free(data);
    rmw_client_free(client);
    axon_session_destroy_client(sid, service_name);
    return NULL;
  }
  data->response_eventfd = (int)res_efd;
  axon_trace_fd_event("create", "client", data->response_eventfd,
                      data->service_name);

  client->implementation_identifier = "rmw_axon";
  client->service_name = data->service_name;
  client->data = data;
  return client;
}

rmw_ret_t rmw_destroy_client(rmw_node_t *node, rmw_client_t *client) {
  (void)node;
  if (client) {
    if (client->data) {
      axon_client_data_t *data = (axon_client_data_t *)client->data;
      axon_trace_fd_event("destroy", "client", data->response_eventfd,
                          data->service_name);
      axon_session_destroy_client(data->session_id, data->service_name);
      if (data->service_name)
        free(data->service_name);
      rmw_free(data);
    }
    rmw_client_free(client);
  }
  return RMW_RET_OK;
}

rmw_ret_t rmw_send_request(const rmw_client_t *client, const void *ros_request,
                           int64_t *sequence_id) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(client, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(ros_request, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(sequence_id, RMW_RET_INVALID_ARGUMENT);

  axon_client_data_t *data = (axon_client_data_t *)client->data;

  const message_type_support_callbacks_t *callbacks =
      get_service_msg_callbacks(data->type_support, true);
  if (!callbacks) {
    RMW_SET_ERROR_MSG("failed to get request callbacks");
    return RMW_RET_ERROR;
  }

  size_t max_size =
      axon_serialized_size_for_message(callbacks, ros_request, 4096);
  if (max_size < 4096)
    max_size = 4096;
  if (max_size > static_cast<size_t>(std::numeric_limits<uint32_t>::max()) - 128) {
    RMW_SET_ERROR_MSG("serialized request too large");
    return RMW_RET_ERROR;
  }

  uint32_t buffer_capacity = static_cast<uint32_t>(max_size + 128);
  uint8_t *buffer = (uint8_t *)malloc(buffer_capacity);
  if (!buffer) {
    RMW_SET_ERROR_MSG("failed to allocate request buffer");
    return RMW_RET_BAD_ALLOC;
  }

  bool serialized = false;
  uint32_t buffer_length = 0;
  for (int attempts = 0; attempts < 20; attempts++) {
    uint32_t attempt_len = buffer_capacity;
    if (serialize_message(callbacks, ros_request, buffer, &attempt_len)) {
      buffer_length = attempt_len;
      serialized = true;
      break;
    }

    if (!axon_grow_serialization_buffer(&buffer, &buffer_capacity,
                                        buffer_capacity + 1)) {
      free(buffer);
      RMW_SET_ERROR_MSG("failed to grow request buffer");
      return RMW_RET_BAD_ALLOC;
    }
  }
  if (!serialized) {
    free(buffer);
    RMW_SET_ERROR_MSG("CDR request serialization failed");
    return RMW_RET_ERROR;
  }

  int64_t seq = axon_session_send_request_with_gid(
      data->session_id, data->service_name, data->client_gid, buffer,
      buffer_length);
  free(buffer);

  if (seq < 0) {
    RMW_SET_ERROR_MSG("axon_session_send_request failed");
    return RMW_RET_ERROR;
  }

  *sequence_id = seq;
  AXON_TRACE_ROS("event=service_call service=%s bytes=%u seq=%ld",
                 data->service_name, buffer_length, static_cast<long>(seq));
  return RMW_RET_OK;
}

rmw_ret_t rmw_take_response(const rmw_client_t *client,
                            rmw_service_info_t *request_header,
                            void *ros_response, bool *taken) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(client, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(request_header, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(ros_response, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(taken, RMW_RET_INVALID_ARGUMENT);

  axon_client_data_t *data = (axon_client_data_t *)client->data;
  *taken = false;

  const message_type_support_callbacks_t *callbacks =
      get_service_msg_callbacks(data->type_support, false);
  if (!callbacks) {
    RMW_SET_ERROR_MSG("failed to get response callbacks");
    return RMW_RET_ERROR;
  }

  uint8_t small_buf[65536];
  uint32_t buf_capacity = sizeof(small_buf);
  uint8_t *buf = small_buf;
  int needs_free = 0;

  // Retry up to 2 times to handle buffer-too-small without consuming data.
  for (int attempt = 0; attempt < 2; attempt++) {
    uint32_t out_len = buf_capacity;
    int64_t request_sequence = 0;
    int ret = axon_session_take_response_for_client(
        data->session_id, data->service_name, &data->next_seq,
        data->client_gid, buf, &out_len, &request_sequence);

    if (ret == 0) {
      memset(request_header, 0, sizeof(*request_header));
      memcpy(request_header->request_id.writer_guid, data->client_gid,
             sizeof(request_header->request_id.writer_guid));
      request_header->request_id.sequence_number = request_sequence;
      if (!deserialize_message(callbacks, buf, out_len, ros_response)) {
        RMW_SET_ERROR_MSG("CDR deserialize response failed");
        *taken = false;
        if (needs_free) free(buf);
        return RMW_RET_ERROR;
      }
      *taken = true;
      AXON_TRACE_ROS("event=service_result service=%s bytes=%u request_seq=%ld",
                     data->service_name, out_len,
                     static_cast<long>(request_sequence));
      if (needs_free) free(buf);
      return RMW_RET_OK;
    }

    if (ret == -2) {
      // Buffer too small — allocate required size and retry
      uint32_t required = out_len;
      uint8_t *new_buf = (uint8_t *)malloc(required);
      if (!new_buf) {
        if (needs_free) free(buf);
        RMW_SET_ERROR_MSG("failed to allocate take_response buffer");
        return RMW_RET_BAD_ALLOC;
      }
      if (needs_free) free(buf);
      buf = new_buf;
      buf_capacity = required;
      needs_free = 1;
      continue;
    }

    break;
  }

  if (needs_free) free(buf);
  return RMW_RET_OK;
}
