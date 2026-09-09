# Bundled QKD beta profiles

These profiles provide the two QuKayDee SAE identities used by the Axon
two-host beta test. They are not selected by a normal build.

A normal build selects neither identity:

```bash
colcon build --packages-select rmw_axon
```

Select SAE 1 on the first QKD host:

```bash
colcon build --packages-select rmw_axon \
  --cmake-args -DAXON_QKD_ROLE=1
```

Select SAE 2 on the second QKD host:

```bash
colcon build --packages-select rmw_axon \
  --cmake-args -DAXON_QKD_ROLE=2
```

CMake installs only the selected profile under `share/rmw_axon/qkd`. After
sourcing the workspace, select QKD with:

```bash
export RMW_IMPLEMENTATION=rmw_axon
export AXON_SECURITY_MODE=qkd
```

Select the standard mode instead with:

```bash
export RMW_IMPLEMENTATION=rmw_axon
export AXON_SECURITY_MODE=classic
```

The included SAE certificates expire on 2027-07-24. These credentials are
beta test fixtures and are not suitable for production identity provisioning.
Replace them with host-specific credentials before exposing the repository or
using it outside the beta account.

For Docker, select the profile while building the image:

```bash
docker build -f docker/Dockerfile \
  --build-arg ROS_DISTRO=humble \
  --build-arg AXON_QKD_ROLE=1 \
  -t rmw_axon:humble-qkd-sae1 .
```

Build a second image with `AXON_QKD_ROLE=2` for the other isolated endpoint.
