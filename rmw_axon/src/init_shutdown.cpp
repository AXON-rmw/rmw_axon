#include "rmw_axon/internal.hpp"

rmw_ret_t rmw_init(const rmw_init_options_t *options, rmw_context_t *context) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(options, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(context, RMW_RET_INVALID_ARGUMENT);

  int32_t domain_id = 0;
  if (options->domain_id != RMW_DEFAULT_DOMAIN_ID) {
    domain_id = options->domain_id;
  }
  int64_t sid = axon_session_create(domain_id);
  if (sid < 0) {
    RMW_SET_ERROR_MSG("axon_session_create failed");
    return RMW_RET_ERROR;
  }

  axon_context_impl_t *impl =
      (axon_context_impl_t *)malloc(sizeof(axon_context_impl_t));
  if (!impl) {
    axon_session_destroy((uint64_t)sid);
    RMW_SET_ERROR_MSG("failed to allocate context impl");
    return RMW_RET_BAD_ALLOC;
  }
  impl->session_id = (uint64_t)sid;
  impl->shutdown_called = false;
  context->impl = (rmw_context_impl_t *)impl;
  context->implementation_identifier = "rmw_axon";
  return RMW_RET_OK;
}

rmw_ret_t rmw_shutdown(rmw_context_t *context) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(context, RMW_RET_INVALID_ARGUMENT);
  if (context->impl) {
    auto *impl = (axon_context_impl_t *)context->impl;
    if (!impl->shutdown_called &&
        axon_session_shutdown(impl->session_id) != 0) {
      RMW_SET_ERROR_MSG("axon_session_shutdown failed");
      return RMW_RET_ERROR;
    }
    impl->shutdown_called = true;
  }
  return RMW_RET_OK;
}

rmw_ret_t rmw_context_fini(rmw_context_t *context) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(context, RMW_RET_INVALID_ARGUMENT);
  if (!context->impl) {
    return RMW_RET_OK;
  }
  uint64_t sid = get_session_id(context);
  if (sid != 0) {
    axon_session_destroy(sid);
  }
  free(context->impl);
  context->impl = NULL;
  return RMW_RET_OK;
}

rmw_ret_t rmw_init_options_init(rmw_init_options_t *init_options,
                                rcutils_allocator_t allocator) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(init_options, RMW_RET_INVALID_ARGUMENT);
  if (NULL != allocator.allocate) {
    init_options->allocator = allocator;
  }
  init_options->implementation_identifier = "rmw_axon";
  init_options->domain_id = RMW_DEFAULT_DOMAIN_ID;
  init_options->enclave = const_cast<char *>("/");
  return RMW_RET_OK;
}

rmw_ret_t rmw_init_options_copy(const rmw_init_options_t *src,
                                rmw_init_options_t *dst) {
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(src, RMW_RET_INVALID_ARGUMENT);
  RCUTILS_CHECK_ARGUMENT_FOR_NULL(dst, RMW_RET_INVALID_ARGUMENT);
  *dst = *src;
  return RMW_RET_OK;
}

const char *rmw_get_serialization_format(void) { return "cdr"; }

rmw_ret_t rmw_init_options_fini(rmw_init_options_t * /*init_options*/) {
  return RMW_RET_OK;
}
