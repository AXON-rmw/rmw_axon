/**
 * @file rmw_axon.h
 * @brief RMW (ROS Middleware) interface declarations for the Axon
 * implementation.
 *
 * Exposes the subset of RMW functions implemented by rmw_axon.
 */

#ifndef RMW_AXON__RMW_AXON_H_
#define RMW_AXON__RMW_AXON_H_

#include "rmw/rmw.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the RMW middleware and create a new Axon session.
 * @param[in] options Initialization options (domain ID, allocator, etc.).
 * @param[out] context Populated RMW context containing the session handle.
 * @return rmw_ret_t RMW_RET_OK on success, RMW_RET_ERROR on failure.
 */
extern rmw_ret_t rmw_init(const rmw_init_options_t *options,
                          rmw_context_t *context);

/**
 * @brief Create a service server on the given node.
 * @param[in] node The ROS node to attach the service to.
 * @param[in] type_support ROSIDL service type support descriptor.
 * @param[in] service_name Fully-qualified service name.
 * @param[in] qos_profile QoS profile for the service communication.
 * @return rmw_service_t* Pointer to the created service, or NULL on failure.
 */
extern rmw_service_t *rmw_create_service(
    const rmw_node_t *node, const rosidl_service_type_support_t *type_support,
    const char *service_name, const rmw_qos_profile_t *qos_profile);

/**
 * @brief Create a service client on the given node.
 * @param[in] node The ROS node to attach the client to.
 * @param[in] type_support ROSIDL service type support descriptor.
 * @param[in] service_name Fully-qualified service name.
 * @param[in] qos_profile QoS profile for the client communication.
 * @return rmw_client_t* Pointer to the created client, or NULL on failure.
 */
extern rmw_client_t *rmw_create_client(
    const rmw_node_t *node, const rosidl_service_type_support_t *type_support,
    const char *service_name, const rmw_qos_profile_t *qos_profile);

#ifdef __cplusplus
}
#endif

#endif
