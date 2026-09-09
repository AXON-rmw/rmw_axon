ARG ROS_DISTRO=humble
FROM ros:${ROS_DISTRO}-ros-base

ARG ROS_DISTRO
# Optional bundled QuKayDee beta profile. Leave empty for the normal build;
# use 1 and 2 for two isolated QKD endpoints.
ARG AXON_QKD_ROLE=""
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    iproute2 \
    iputils-ping \
    libfastcdr-dev \
    net-tools \
    pkg-config \
    procps \
    python3-colcon-common-extensions \
    ros-${ROS_DISTRO}-action-tutorials-cpp \
    ros-${ROS_DISTRO}-ament-cmake-ros \
    ros-${ROS_DISTRO}-demo-nodes-cpp \
    ros-${ROS_DISTRO}-image-tools \
    ros-${ROS_DISTRO}-lifecycle \
    ros-${ROS_DISTRO}-pluginlib \
    ros-${ROS_DISTRO}-rcutils \
    ros-${ROS_DISTRO}-rmw \
    ros-${ROS_DISTRO}-rosidl-runtime-c \
    ros-${ROS_DISTRO}-rosidl-typesupport-c \
    ros-${ROS_DISTRO}-rosidl-typesupport-cpp \
    ros-${ROS_DISTRO}-rosidl-typesupport-fastrtps-c \
    ros-${ROS_DISTRO}-rosidl-typesupport-fastrtps-cpp \
    ros-${ROS_DISTRO}-rosidl-typesupport-introspection-c \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal

ENV PATH=/root/.cargo/bin:$PATH

WORKDIR /axon_ws/src/rmw_axon
COPY . .

RUN source /opt/ros/${ROS_DISTRO}/setup.bash \
    && cd /axon_ws \
    && colcon build --packages-select rmw_axon \
        --cmake-args -DAXON_QKD_ROLE=${AXON_QKD_ROLE}

ENV AXON_DAEMON_PATH=/axon_ws/install/rmw_axon/lib/axon_daemon
WORKDIR /axon_ws

CMD ["/bin/bash"]
