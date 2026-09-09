cmake_minimum_required(VERSION 3.16)
project(rmw_axon)

find_package(ament_cmake_ros REQUIRED)
find_package(rmw REQUIRED)
find_package(rcutils REQUIRED)
find_package(rosidl_typesupport_c REQUIRED)
find_package(rosidl_typesupport_cpp REQUIRED)
find_package(rosidl_typesupport_introspection_c REQUIRED)
find_package(rosidl_runtime_c REQUIRED)
find_package(rosidl_typesupport_fastrtps_c REQUIRED)
find_package(rosidl_typesupport_fastrtps_cpp REQUIRED)
find_package(fastcdr REQUIRED)
find_package(pluginlib REQUIRED)

# Build the Rust library via cargo
set(CARGO_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo")
set(AXON_CORE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../axon_core")
set(AXON_CORE_LIB "${CARGO_TARGET_DIR}/release/libaxon_core.a")
set(AXON_DAEMON_BIN "${CARGO_TARGET_DIR}/release/axon_daemon")

add_custom_target(axon_core ALL
    COMMAND "${CMAKE_COMMAND}" -E env
        --unset=MAKEFLAGS
        --unset=MFLAGS
        --unset=CARGO_MAKEFLAGS
        cargo build --release --locked --manifest-path "${AXON_CORE_SRC}/Cargo.toml"
        --target-dir "${CARGO_TARGET_DIR}"
    BYPRODUCTS "${CARGO_TARGET_DIR}/release/libaxon_core.a"
               "${AXON_DAEMON_BIN}"
    COMMENT "Building axon_core (Rust)"
)

add_library(rmw_axon SHARED
    src/graph.cpp
    src/guard_condition.cpp
    src/init_shutdown.cpp
    src/misc_stubs.cpp
    src/node.cpp
    src/pubsub.cpp
    src/serialization.cpp
    src/service.cpp
    src/wait.cpp
)
add_dependencies(rmw_axon axon_core)
target_link_libraries(rmw_axon
    "${AXON_CORE_LIB}"
    ${CMAKE_DL_LIBS}
    rmw::rmw
    fastcdr
    rosidl_typesupport_fastrtps_cpp::rosidl_typesupport_fastrtps_cpp
    rosidl_typesupport_fastrtps_c::rosidl_typesupport_fastrtps_c
    rosidl_typesupport_c::rosidl_typesupport_c
    rosidl_typesupport_cpp::rosidl_typesupport_cpp
    rosidl_typesupport_introspection_c::rosidl_typesupport_introspection_c
    rosidl_runtime_c::rosidl_runtime_c
)
target_include_directories(rmw_axon
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<INSTALL_INTERFACE:include>"
)

install(TARGETS rmw_axon
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(PROGRAMS "${AXON_DAEMON_BIN}" DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

# A normal build installs no SAE identity and is ready for classic mode.
# QKD beta builds explicitly select one of the bundled QuKayDee identities
# with --cmake-args -DAXON_QKD_ROLE=1 or 2.
set(AXON_QKD_ROLE "" CACHE STRING "Bundled QKD beta role (empty, 1, or 2)")
set_property(CACHE AXON_QKD_ROLE PROPERTY STRINGS "" 1 2)
if(AXON_QKD_ROLE STREQUAL "")
    message(STATUS "Building AXON without a bundled QKD SAE profile")
elseif(AXON_QKD_ROLE STREQUAL "1" OR AXON_QKD_ROLE STREQUAL "2")
    set(AXON_QKD_BETA_PROFILE_DIR
        "${CMAKE_CURRENT_SOURCE_DIR}/../qkd_beta_profiles/sae-${AXON_QKD_ROLE}")
    set(AXON_QKD_BETA_PROFILE_FILES
        "${AXON_QKD_BETA_PROFILE_DIR}/profile"
        "${AXON_QKD_BETA_PROFILE_DIR}/account-4624-server-ca-qukaydee-com.crt"
        "${AXON_QKD_BETA_PROFILE_DIR}/sae-${AXON_QKD_ROLE}.crt"
        "${AXON_QKD_BETA_PROFILE_DIR}/sae-${AXON_QKD_ROLE}.key")
    foreach(AXON_QKD_BETA_PROFILE_FILE IN LISTS AXON_QKD_BETA_PROFILE_FILES)
        if(NOT EXISTS "${AXON_QKD_BETA_PROFILE_FILE}")
            message(FATAL_ERROR
                "Bundled QKD beta profile is incomplete: ${AXON_QKD_BETA_PROFILE_FILE}")
        endif()
    endforeach()

    message(STATUS
        "Installing bundled AXON QKD beta profile for SAE ${AXON_QKD_ROLE}")
    install(
        DIRECTORY "${AXON_QKD_BETA_PROFILE_DIR}/"
        DESTINATION "share/${PROJECT_NAME}/qkd"
        FILE_PERMISSIONS OWNER_READ OWNER_WRITE
        DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
    )
else()
    message(FATAL_ERROR "AXON_QKD_ROLE must be empty, 1, or 2")
endif()

pluginlib_export_plugin_description_file(rmw_axon plugin_description.xml)

ament_package()
