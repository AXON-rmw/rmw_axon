#include "rmw_axon/internal.hpp"

#include <cstring>
#include <vector>

static rmw_ret_t axon_fetch_graph_buffer(
    int32_t (*query_fn)(uint64_t, uint8_t *, uint32_t, uint32_t *),
    uint64_t session_id, std::vector<uint8_t> &buf, uint32_t *count) {
  size_t capacity = 65536;
  constexpr size_t kMaxGraphBuffer = 16 * 1024 * 1024;
  while (capacity <= kMaxGraphBuffer) {
    buf.assign(capacity, 0);
    *count = 0;
    int32_t ret =
        query_fn(session_id, buf.data(), static_cast<uint32_t>(buf.size()), count);
    if (ret == 0)
      return RMW_RET_OK;
    if (ret != -2)
      return RMW_RET_ERROR;
    capacity *= 2;
  }
  return RMW_RET_ERROR;
}

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

rmw_ret_t rmw_get_node_names(const rmw_node_t *node,
                             rcutils_string_array_t *node_names,
                             rcutils_string_array_t *node_namespaces) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(node_names, RMW_RET_INVALID_ARGUMENT);

  uint64_t session_id =
      node->data ? ((axon_node_data_t *)node->data)->session_id : 0;

  std::vector<uint8_t> buf;
  uint32_t count = 0;
  rmw_ret_t fetch_ret = axon_fetch_graph_buffer(
      axon_session_get_node_names_with_namespaces, session_id, buf, &count);
  if (fetch_ret != RMW_RET_OK)
    return fetch_ret;

  rcutils_allocator_t alloc = rcutils_get_default_allocator();
  if (rcutils_string_array_init(node_names, count, &alloc) != RCUTILS_RET_OK) {
    return RMW_RET_BAD_ALLOC;
  }
  if (node_namespaces) {
    if (rcutils_string_array_init(node_namespaces, count, &alloc) !=
        RCUTILS_RET_OK) {
      rcutils_ret_t _rc = rcutils_string_array_fini(node_names);
      (void)_rc;
      return RMW_RET_BAD_ALLOC;
    }
  }

  const uint8_t *p = buf.data();
  const uint8_t *end = buf.data() + buf.size();
  for (uint32_t i = 0; i < count; i++) {
    const char *name = nullptr;
    const char *node_namespace = nullptr;
    size_t name_len = 0;
    size_t namespace_len = 0;
    if (!axon_next_c_string(p, end, name, name_len) ||
        !axon_next_c_string(p, end, node_namespace, namespace_len)) {
      if (node_namespaces) {
        rcutils_ret_t _rc1 = rcutils_string_array_fini(node_namespaces);
        (void)_rc1;
      }
      rcutils_ret_t _rc2 = rcutils_string_array_fini(node_names);
      (void)_rc2;
      return RMW_RET_ERROR;
    }
    node_names->data[i] = strndup(name, name_len);
    if (node_namespaces) {
      node_namespaces->data[i] = strndup(node_namespace, namespace_len);
    }
    if (!node_names->data[i] ||
        (node_namespaces && !node_namespaces->data[i])) {
      if (node_namespaces) {
        rcutils_ret_t _rc1 = rcutils_string_array_fini(node_namespaces);
        (void)_rc1;
      }
      rcutils_ret_t _rc2 = rcutils_string_array_fini(node_names);
      (void)_rc2;
      return RMW_RET_BAD_ALLOC;
    }
  }

  return RMW_RET_OK;
}

rmw_ret_t rmw_get_node_names_with_enclaves(
    const rmw_node_t *node, rcutils_string_array_t *node_names,
    rcutils_string_array_t *node_namespaces, rcutils_string_array_t *enclaves) {
  if (!node || !node_names || !node_namespaces || !enclaves)
    return RMW_RET_INVALID_ARGUMENT;
  uint64_t sid = node->data ? ((axon_node_data_t *)node->data)->session_id : 0;
  std::vector<uint8_t> buf;
  uint32_t count = 0;
  rmw_ret_t fetch_ret = axon_fetch_graph_buffer(
      axon_session_get_node_names_with_enclaves, sid, buf, &count);
  if (fetch_ret != RMW_RET_OK)
    return fetch_ret;
  rcutils_allocator_t alloc = rcutils_get_default_allocator();
  if (rcutils_string_array_init(node_names, count, &alloc) != RCUTILS_RET_OK)
    return RMW_RET_BAD_ALLOC;
  if (rcutils_string_array_init(node_namespaces, count, &alloc) !=
      RCUTILS_RET_OK) {
    rcutils_ret_t _rc = rcutils_string_array_fini(node_names);
    (void)_rc;
    return RMW_RET_BAD_ALLOC;
  }
  if (rcutils_string_array_init(enclaves, count, &alloc) != RCUTILS_RET_OK) {
    rcutils_ret_t _rc1 = rcutils_string_array_fini(node_namespaces);
    rcutils_ret_t _rc2 = rcutils_string_array_fini(node_names);
    (void)_rc1;
    (void)_rc2;
    return RMW_RET_BAD_ALLOC;
  }
  const uint8_t *p = buf.data();
  const uint8_t *end = buf.data() + buf.size();
  for (uint32_t i = 0; i < count; i++) {
    const char *name = nullptr;
    const char *node_namespace = nullptr;
    size_t name_len = 0;
    size_t namespace_len = 0;
    if (!axon_next_c_string(p, end, name, name_len) ||
        !axon_next_c_string(p, end, node_namespace, namespace_len)) {
      rcutils_ret_t _rc1 = rcutils_string_array_fini(enclaves);
      rcutils_ret_t _rc2 = rcutils_string_array_fini(node_namespaces);
      rcutils_ret_t _rc3 = rcutils_string_array_fini(node_names);
      (void)_rc1;
      (void)_rc2;
      (void)_rc3;
      return RMW_RET_ERROR;
    }
    node_names->data[i] = strndup(name, name_len);
    node_namespaces->data[i] = strndup(node_namespace, namespace_len);
    if (!node_names->data[i]) {
      rcutils_ret_t _rc1 = rcutils_string_array_fini(enclaves);
      rcutils_ret_t _rc2 = rcutils_string_array_fini(node_namespaces);
      rcutils_ret_t _rc3 = rcutils_string_array_fini(node_names);
      (void)_rc1;
      (void)_rc2;
      (void)_rc3;
      return RMW_RET_BAD_ALLOC;
    }
    if (!node_namespaces->data[i]) {
      rcutils_ret_t _rc1 = rcutils_string_array_fini(enclaves);
      rcutils_ret_t _rc2 = rcutils_string_array_fini(node_namespaces);
      rcutils_ret_t _rc3 = rcutils_string_array_fini(node_names);
      (void)_rc1;
      (void)_rc2;
      (void)_rc3;
      return RMW_RET_BAD_ALLOC;
    }
    enclaves->data[i] = strndup("/", 1);
    if (!enclaves->data[i]) {
      rcutils_ret_t _rc1 = rcutils_string_array_fini(enclaves);
      rcutils_ret_t _rc2 = rcutils_string_array_fini(node_namespaces);
      rcutils_ret_t _rc3 = rcutils_string_array_fini(node_names);
      (void)_rc1;
      (void)_rc2;
      (void)_rc3;
      return RMW_RET_BAD_ALLOC;
    }
  }
  return RMW_RET_OK;
}

rmw_ret_t
rmw_get_topic_names_and_types(const rmw_node_t *node,
                              rcutils_allocator_t *allocator, bool /*no_demangle*/,
                              rmw_names_and_types_t *topic_names_and_types) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(allocator, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(topic_names_and_types,
                                  RMW_RET_INVALID_ARGUMENT);

  uint64_t session_id =
      node->data ? ((axon_node_data_t *)node->data)->session_id : 0;
  std::vector<uint8_t> names_buf;
  uint32_t names_count = 0;

  rmw_ret_t fetch_ret =
      axon_fetch_graph_buffer(axon_session_get_topic_names, session_id,
                              names_buf, &names_count);
  if (fetch_ret != RMW_RET_OK)
    return fetch_ret;

  if (names_count == 0) {
    topic_names_and_types->names.size = 0;
    topic_names_and_types->names.data = NULL;
    topic_names_and_types->types = NULL;
    return RMW_RET_OK;
  }

  rmw_ret_t r =
      rmw_names_and_types_init(topic_names_and_types, names_count, allocator);
  if (r != RMW_RET_OK)
    return RMW_RET_BAD_ALLOC;

  const uint8_t *p = names_buf.data();
  const uint8_t *end = names_buf.data() + names_buf.size();
  for (uint32_t i = 0; i < names_count; i++) {
    const char *topic_name = nullptr;
    size_t len = 0;
    if (!axon_next_c_string(p, end, topic_name, len)) {
      rmw_ret_t _ret = rmw_names_and_types_fini(topic_names_and_types);
      (void)_ret;
      return RMW_RET_ERROR;
    }
    topic_names_and_types->names.data[i] = strndup(topic_name, len);
    if (!topic_names_and_types->names.data[i]) {
      rmw_ret_t _ret = rmw_names_and_types_fini(topic_names_and_types);
      (void)_ret;
      return RMW_RET_BAD_ALLOC;
    }

    char *topic_type = axon_session_get_topic_type(session_id, topic_name);
    const char *type_str = topic_type ? topic_type : "unknown";

    if (rcutils_string_array_init(&topic_names_and_types->types[i], 1,
                                  allocator) != RCUTILS_RET_OK) {
      if (topic_type)
        free(topic_type);
      rmw_ret_t _ret = rmw_names_and_types_fini(topic_names_and_types);
      (void)_ret;
      return RMW_RET_BAD_ALLOC;
    }
    topic_names_and_types->types[i].data[0] =
        strndup(type_str, strlen(type_str));
    if (!topic_names_and_types->types[i].data[0]) {
      if (topic_type)
        free(topic_type);
      rmw_ret_t _ret = rmw_names_and_types_fini(topic_names_and_types);
      (void)_ret;
      return RMW_RET_BAD_ALLOC;
    }
    if (topic_type)
      free(topic_type);
  }

  return RMW_RET_OK;
}

rmw_ret_t rmw_get_service_names_and_types(
    const rmw_node_t *node, rcutils_allocator_t *allocator,
    rmw_names_and_types_t *service_names_and_types) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(node, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(allocator, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(service_names_and_types,
                                  RMW_RET_INVALID_ARGUMENT);

  uint64_t session_id =
      node->data ? ((axon_node_data_t *)node->data)->session_id : 0;
  size_t count = 0;
  char **names_arr = nullptr;
  char **types_arr = nullptr;

  int ret = axon_session_get_service_names_and_types(session_id, &count,
                                                     &names_arr, &types_arr);
  if (ret != 0)
    return RMW_RET_ERROR;

  if (count == 0) {
    service_names_and_types->names.size = 0;
    service_names_and_types->names.data = NULL;
    service_names_and_types->types = NULL;
    return RMW_RET_OK;
  }

  rmw_ret_t r =
      rmw_names_and_types_init(service_names_and_types, count, allocator);
  if (r != RMW_RET_OK) {
    std::free(names_arr);
    std::free(types_arr);
    return RMW_RET_BAD_ALLOC;
  }

  for (size_t i = 0; i < count; i++) {
    service_names_and_types->names.data[i] =
        strndup(names_arr[i], strlen(names_arr[i]));
    if (!service_names_and_types->names.data[i]) {
      rmw_ret_t _ret = rmw_names_and_types_fini(service_names_and_types);
      (void)_ret;
      std::free(names_arr);
      std::free(types_arr);
      return RMW_RET_BAD_ALLOC;
    }

    if (rcutils_string_array_init(&service_names_and_types->types[i], 1,
                                  allocator) != RCUTILS_RET_OK) {
      rmw_ret_t _ret = rmw_names_and_types_fini(service_names_and_types);
      (void)_ret;
      std::free(names_arr);
      std::free(types_arr);
      return RMW_RET_BAD_ALLOC;
    }
    service_names_and_types->types[i].data[0] =
        strndup(types_arr[i], strlen(types_arr[i]));
    if (!service_names_and_types->types[i].data[0]) {
      rmw_ret_t _ret = rmw_names_and_types_fini(service_names_and_types);
      (void)_ret;
      std::free(names_arr);
      std::free(types_arr);
      return RMW_RET_BAD_ALLOC;
    }
  }

  for (size_t i = 0; i < count; i++) {
    std::free(names_arr[i]);
    std::free(types_arr[i]);
  }
  std::free(names_arr);
  std::free(types_arr);

  return RMW_RET_OK;
}

rmw_ret_t rmw_service_server_is_available(const rmw_node_t *node,
                                          const rmw_client_t *client,
                                          bool *is_available) {
  if (!node || !client || !is_available)
    return RMW_RET_INVALID_ARGUMENT;
  uint64_t sid = node->data ? ((axon_node_data_t *)node->data)->session_id : 0;
  axon_client_data_t *data = (axon_client_data_t *)client->data;
  int32_t avail = 0;
  if (axon_session_service_available(sid, data->service_name, &avail) != 0)
    return RMW_RET_ERROR;
  *is_available = avail != 0;
  return RMW_RET_OK;
}
