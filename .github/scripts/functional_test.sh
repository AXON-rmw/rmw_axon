#!/usr/bin/env bash
# Functional test for rmw_axon, shared by every per-distro CI workflow and by
# local Docker runs. Exercises the transport end to end — publish/subscribe,
# a service round trip, and graph introspection — not just a single message.
#
# Assumes ROS 2 and the built rmw_axon workspace are already sourced, or sources
# them from the conventional paths when run standalone.
set -eo pipefail

: "${ROS_DISTRO:?ROS_DISTRO must be set}"
if ! command -v ros2 >/dev/null 2>&1; then
  source "/opt/ros/${ROS_DISTRO}/setup.bash"
fi
[[ -f "install/setup.bash" ]] || {
  echo "::error::install/setup.bash not found; build rmw_axon before running this test"
  exit 1
}
source "install/setup.bash"

export RMW_IMPLEMENTATION=rmw_axon
export ROS_DOMAIN_ID=211
export AXON_DAEMON_PATH="${AXON_DAEMON_PATH:-$PWD/install/rmw_axon/lib/axon_daemon}"

log_dir="$(mktemp -d)"
cleanup() { pkill -x axon_daemon 2>/dev/null || true; pkill -f demo_nodes_cpp 2>/dev/null || true; }
trap cleanup EXIT
fail() { echo "::error::rmw_axon functional test failed: $1"; exit 1; }

reset_state() {
  pkill -f demo_nodes_cpp 2>/dev/null || true
  pkill -x axon_daemon 2>/dev/null || true
  rm -f /tmp/axon_daemon.pid /dev/shm/axon_daemon \
    /dev/shm/axon_domain_*_topic_* /dev/shm/axon_topic_* 2>/dev/null || true
  sleep 1
}

echo "== rmw_axon functional test (${ROS_DISTRO}, RMW=${RMW_IMPLEMENTATION}) =="

# 1) Publish / subscribe over shared memory.
reset_state
timeout 15 ros2 run demo_nodes_cpp listener > "$log_dir/listener.log" 2>&1 &
listener_pid=$!
sleep 3
timeout 8 ros2 run demo_nodes_cpp talker > "$log_dir/talker.log" 2>&1 || true
wait "$listener_pid" 2>/dev/null || true
grep -q "I heard: \[Hello World:" "$log_dir/listener.log" || fail "pub/sub: listener received no messages"
echo "  [ok] publish/subscribe"

# 2) Service round trip (AddTwoInts).
reset_state
timeout 18 ros2 run demo_nodes_cpp add_two_ints_server > "$log_dir/server.log" 2>&1 &
sleep 3
timeout 12 ros2 service call /add_two_ints example_interfaces/srv/AddTwoInts "{a: 7, b: 35}" \
  > "$log_dir/service.log" 2>&1 || true
grep -q "sum=42" "$log_dir/service.log" || fail "service: AddTwoInts did not return sum=42"
echo "  [ok] service call"

# 3) Graph introspection (topics and nodes are discoverable).
reset_state
timeout 14 ros2 run demo_nodes_cpp talker > /dev/null 2>&1 &
sleep 4
ros2 topic list > "$log_dir/topics.log" 2>&1 || true
ros2 node list > "$log_dir/nodes.log" 2>&1 || true
grep -q "/chatter" "$log_dir/topics.log" || fail "graph: /chatter not listed by 'ros2 topic list'"
grep -q "/talker" "$log_dir/nodes.log" || fail "graph: /talker not listed by 'ros2 node list'"
echo "  [ok] graph introspection"

echo "== all rmw_axon functional tests passed =="
