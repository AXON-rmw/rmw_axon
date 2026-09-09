#include "rmw_axon/internal.hpp"

rmw_node_t *rmw_create_node(rmw_context_t *context, const char *name,
                            const char *namespace_) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(context, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(name, NULL);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(namespace_, NULL);

  rmw_node_t *node = rmw_node_allocate();
  if (!node) {
    RMW_SET_ERROR_MSG("failed to allocate node");
    return NULL;
  }

  axon_node_data_t *node_data =
      (axon_node_data_t *)rmw_allocate(sizeof(axon_node_data_t));
  if (!node_data) {
    rmw_node_free(node);
    RMW_SET_ERROR_MSG("failed to allocate node data");
    return NULL;
  }
  node_data->session_id = get_session_id(context);
  node_data->graph_gc = NULL;

  node->implementation_identifier = "rmw_axon";
  node->data = node_data;
  node->context = context;
  node->name = strdup(name);
  if (!node->name) {
    rmw_free(node_data);
    rmw_node_free(node);
    RMW_SET_ERROR_MSG("failed to duplicate node name");
    return NULL;
  }
  node->namespace_ = strdup(namespace_);
  if (!node->namespace_) {
    free((void *)node->name);
    rmw_free(node_data);
    rmw_node_free(node);
    RMW_SET_ERROR_MSG("failed to duplicate namespace");
    return NULL;
  }

  axon_session_set_node_name(node_data->session_id, name, namespace_);

  return node;
}

rmw_ret_t rmw_destroy_node(rmw_node_t *node) {
  if (node) {
    if (node->data) {
      axon_node_data_t *nd = (axon_node_data_t *)node->data;
      if (nd->graph_gc) {
        axon_guard_condition_data_t *gc_data =
            (axon_guard_condition_data_t *)nd->graph_gc->data;
        if (gc_data) {
          axon_session_unregister_graph_event_fd(nd->session_id,
                                                 gc_data->event_fd);
        }
        rmw_ret_t _ret = rmw_destroy_guard_condition(nd->graph_gc);
        (void)_ret;
        nd->graph_gc = NULL;
      }
      rmw_free(node->data);
    }
    free((void *)node->name);
    free((void *)node->namespace_);
    rmw_node_free(node);
  }
  return RMW_RET_OK;
}

const rmw_guard_condition_t *
rmw_node_get_graph_guard_condition(const rmw_node_t *node) {
  if (!node)
    return NULL;
  rmw_node_t *mutable_node = const_cast<rmw_node_t *>(node);
  axon_node_data_t *nd = (axon_node_data_t *)mutable_node->data;
  if (!nd) {
    nd = (axon_node_data_t *)rmw_allocate(sizeof(axon_node_data_t));
    if (!nd)
      return NULL;
    nd->session_id = 0;
    nd->graph_gc = NULL;
    mutable_node->data = nd;
  }
  if (!nd->graph_gc) {
    nd->graph_gc = rmw_create_guard_condition(mutable_node->context);
    if (!nd->graph_gc)
      return NULL;
    if (!axon_guard_condition_use_dedicated_eventfd(nd->graph_gc)) {
      rmw_ret_t _ret = rmw_destroy_guard_condition(nd->graph_gc);
      (void)_ret;
      nd->graph_gc = NULL;
      return NULL;
    }
    axon_guard_condition_data_t *gc_data =
        (axon_guard_condition_data_t *)nd->graph_gc->data;
    if (!gc_data ||
        axon_session_register_graph_event_fd(nd->session_id,
                                             gc_data->event_fd) != 0) {
      rmw_ret_t _ret = rmw_destroy_guard_condition(nd->graph_gc);
      (void)_ret;
      nd->graph_gc = NULL;
      RMW_SET_ERROR_MSG("failed to register graph guard condition eventfd");
      return NULL;
    }
  }
  return nd->graph_gc;
}
