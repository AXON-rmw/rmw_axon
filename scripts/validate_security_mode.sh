#!/usr/bin/env bash
#
# Visible AXON classic/QKD validation.
#
# Usage:
#   validate_security_mode.sh classic demo
#   validate_security_mode.sh classic startup
#   validate_security_mode.sh classic listener
#   validate_security_mode.sh classic talker
#   validate_security_mode.sh qkd demo 1
#   validate_security_mode.sh qkd startup 1
#   validate_security_mode.sh qkd listener 1
#   validate_security_mode.sh qkd talker 2
#
# For networks without multicast discovery:
#   AXON_TEST_PEER=192.0.2.10:7402 validate_security_mode.sh ...

set -euo pipefail

script_path="${BASH_SOURCE[0]}"
script_dir="$(cd -- "$(dirname -- "$script_path")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"

usage() {
  cat <<EOF
Usage:
  validate_security_mode.sh classic demo|listener|talker
  validate_security_mode.sh qkd     demo|listener|talker 1|2

Examples:
  $0 classic demo
  $0 qkd demo 1
  $0 qkd listener 1
  $0 qkd talker 2

Environment:
  AXON_TEST_PEER=IP:PORT     Static peer if multicast is unavailable
  AXON_TEST_PORT=PORT        Daemon port (default: 7402; startup uses a test port)
  AXON_TEST_DURATION=SECONDS demo/listener/talker duration
  AXON_TEST_PREFIX=PATH      Override the installed rmw_axon prefix
  AXON_TEST_ALLOW_EXISTING=1 Allow another daemon only for isolated diagnostics
  ROS_DOMAIN_ID=ID           ROS domain shared by both hosts (default: 90)
EOF
}

fail() {
  echo
  echo "[FAIL] $*" >&2
  exit 1
}

ok() {
  echo "[ OK ] $*"
}

mode="${1:-}"
action="${2:-}"
expected_role="${3:-}"

case "$mode" in
  classic | qkd) ;;
  *)
    usage
    fail "The mode must be classic or qkd"
    ;;
esac

case "$action" in
  demo | startup | listener | talker) ;;
  *)
    usage
    fail "The action must be demo, startup, listener, or talker"
    ;;
esac

if [[ "$mode" == "qkd" ]]; then
  [[ "$expected_role" == "1" || "$expected_role" == "2" ]] ||
    fail "QKD tests require the expected SAE role: 1 or 2"
elif [[ -n "$expected_role" ]]; then
  fail "Classic mode has no SAE role. Run: $0 classic $action"
fi

if [[ -n "${AXON_TEST_PREFIX:-}" ]]; then
  axon_prefix="$AXON_TEST_PREFIX"
else
  axon_prefix=""
  if command -v ros2 >/dev/null 2>&1; then
    axon_prefix="$(ros2 pkg prefix rmw_axon 2>/dev/null || true)"
  fi

  local_setup="$repo_root/install/setup.bash"
  if [[ -z "$axon_prefix" && -f "$local_setup" ]]; then
    # A source checkout may itself be the colcon workspace. Loading its
    # generated setup here affects this script and its child ROS processes.
    set +u
    # shellcheck disable=SC1090
    source "$local_setup"
    set -u
    if command -v ros2 >/dev/null 2>&1; then
      axon_prefix="$(ros2 pkg prefix rmw_axon 2>/dev/null || true)"
    fi
    if [[ -n "$axon_prefix" ]]; then
      echo "[INFO] Automatically loaded $local_setup"
    fi
  fi

  if [[ -z "$axon_prefix" ]]; then
    cat >&2 <<EOF

AXON is not built or sourced. From the repository root run:

  source /opt/ros/\${ROS_DISTRO:-humble}/setup.bash
  colcon build --packages-select rmw_axon
  source install/setup.bash
EOF
    fail "No installed rmw_axon package was found"
  fi
fi

daemon_path="$axon_prefix/lib/axon_daemon"
[[ -x "$daemon_path" ]] ||
  fail "Installed daemon not found: $daemon_path"

if [[ "$action" != "startup" ]]; then
  command -v ros2 >/dev/null 2>&1 ||
    fail "ros2 is unavailable; source ROS 2 and the AXON workspace first"
  ros2 pkg prefix demo_nodes_cpp >/dev/null 2>&1 ||
    fail "demo_nodes_cpp is not installed"
fi

profile_dir="$axon_prefix/share/rmw_axon/qkd"
if [[ "$mode" == "qkd" ]]; then
  [[ -f "$profile_dir/profile" ]] ||
    fail "No installed QKD profile. Run: cd $repo_root && colcon build --packages-select rmw_axon --cmake-args -DAXON_QKD_ROLE=$expected_role"

  installed_role="$(sed -n 's/^role=//p' "$profile_dir/profile" | head -n 1)"
  account_id="$(sed -n 's/^account_id=//p' "$profile_dir/profile" | head -n 1)"
  [[ "$installed_role" == "$expected_role" ]] ||
    fail "This installation contains SAE $installed_role, not SAE $expected_role. Rebuild with: cd $repo_root && colcon build --packages-select rmw_axon --cmake-args -DAXON_QKD_ROLE=$expected_role"
  [[ "$account_id" =~ ^[0-9]+$ ]] ||
    fail "The installed QKD profile has an invalid account_id"

  ca_file="$profile_dir/account-${account_id}-server-ca-qukaydee-com.crt"
  cert_file="$profile_dir/sae-${installed_role}.crt"
  key_file="$profile_dir/sae-${installed_role}.key"
  [[ -f "$ca_file" && -f "$cert_file" && -f "$key_file" ]] ||
    fail "The installed QKD profile is incomplete"

  ok "Installed profile: SAE $installed_role, account $account_id"

  command -v curl >/dev/null 2>&1 ||
    fail "curl is required for the visible KME mTLS check"
  if [[ "$installed_role" == "1" ]]; then
    peer_role="2"
  else
    peer_role="1"
  fi
  status_url="https://kme-${installed_role}.acct-${account_id}.etsi-qkd-api.qukaydee.com/api/v1/keys/sae-${peer_role}/status"
  echo "== KME mutual-TLS status =="
  curl --fail --silent --show-error --max-time 10 \
    --cacert "$ca_file" \
    --cert "$cert_file" \
    --key "$key_file" \
    "$status_url"
  echo
  ok "KME accepted the SAE certificate over mutual TLS"
else
  if [[ -f "$profile_dir/profile" ]]; then
    installed_role="$(sed -n 's/^role=//p' "$profile_dir/profile" | head -n 1)"
    echo "[INFO] An SAE $installed_role profile is installed but classic mode will not use it"
  else
    ok "Normal installation contains no SAE profile"
  fi
fi

isolated_startup=0
if [[ "$action" == "startup" && -z "${AXON_TEST_PORT:-}" ]]; then
  # A startup-only check does not run a ROS node. Give it a separate port so
  # it can safely inspect the selected build while the user's daemon remains.
  test_port=$((20000 + RANDOM % 30000))
  isolated_startup=1
else
  test_port="${AXON_TEST_PORT:-7402}"
fi

if ! [[ "$test_port" =~ ^[0-9]+$ ]] ||
  ((test_port < 1 || test_port > 65535)); then
  fail "AXON_TEST_PORT must be a valid TCP/UDP port"
fi

reuse_existing_daemon=0
existing_daemon_pid="$(pgrep -o -x axon_daemon || true)"
if [[ -n "$existing_daemon_pid" && "${AXON_TEST_ALLOW_EXISTING:-0}" != "1" ]]; then
  if [[ "$isolated_startup" == "1" ]]; then
    echo "[INFO] An AXON daemon is already running; startup check uses isolated port $test_port"
  elif [[ "$action" == "demo" ]]; then
    existing_mode="$(
      tr '\0' '\n' <"/proc/$existing_daemon_pid/environ" 2>/dev/null |
        sed -n 's/^AXON_SECURITY_MODE=//p' | tail -n 1
    )"
    existing_mode="${existing_mode:-classic}"
    if [[ "$existing_mode" == "$mode" ]]; then
      reuse_existing_daemon=1
      echo "[INFO] Reusing the existing $mode daemon (PID $existing_daemon_pid) for the local demo"
    else
      echo "[INFO] Switching the local demo daemon from $existing_mode to $mode"
      kill -TERM "$existing_daemon_pid"
      for _ in $(seq 1 50); do
        kill -0 "$existing_daemon_pid" 2>/dev/null || break
        sleep 0.1
      done
      kill -0 "$existing_daemon_pid" 2>/dev/null &&
        fail "The existing daemon did not stop cleanly"
      existing_daemon_pid=""
    fi
  else
    echo "Existing AXON daemon processes:"
    pgrep -a -x axon_daemon || true
    echo
    echo "After closing any other AXON/ROS work, stop it with:"
    echo "  pkill -TERM -x axon_daemon"
    echo "Then repeat:"
    echo "  $0 $mode $action${expected_role:+ $expected_role}"
    fail "An existing AXON daemon prevents an isolated end-to-end test"
  fi
fi

export RMW_IMPLEMENTATION=rmw_axon
export ROS_DOMAIN_ID="${ROS_DOMAIN_ID:-90}"
export AXON_SECURITY_MODE="$mode"
export AXON_QUIC_CIPHER="${AXON_QUIC_CIPHER:-chacha20}"
export AXON_DAEMON_PATH="$daemon_path"
export AXON_DAEMON_PORT="$test_port"

# Ensure this test proves installed-profile discovery rather than inheriting
# an unrelated shell configuration.
unset AXON_QKD_PROFILE_DIR
unset AXON_QKD_KME_BASE_URL
unset AXON_QKD_LOCAL_SAE_ID
unset AXON_QKD_CA_CERT
unset AXON_QKD_CLIENT_CERT
unset AXON_QKD_CLIENT_KEY
unset AXON_QKD_PEER_SAE_ID

if [[ -n "${AXON_TEST_PEER:-}" ]]; then
  export AXON_DAEMON_PEERS="$AXON_TEST_PEER"
  echo "[INFO] Static peer: $AXON_DAEMON_PEERS"
  if [[ "$mode" == "qkd" ]]; then
    export AXON_QKD_PEER_SAE_ID="sae-${peer_role}"
    echo "[INFO] Static peer QKD identity: $AXON_QKD_PEER_SAE_ID"
  fi
fi

log_dir="$(mktemp -d "/tmp/axon-security-${mode}.XXXXXX")"
daemon_log="$log_dir/daemon.log"
node_log="$log_dir/${action}.log"
pid_file="$log_dir/axon_daemon.pid"

daemon_pid=""
node_pid=""
second_node_pid=""
cleanup() {
  if [[ -n "$second_node_pid" ]] && kill -0 "$second_node_pid" 2>/dev/null; then
    kill -TERM "$second_node_pid" 2>/dev/null || true
    wait "$second_node_pid" 2>/dev/null || true
  fi
  if [[ -n "$node_pid" ]] && kill -0 "$node_pid" 2>/dev/null; then
    kill -TERM "$node_pid" 2>/dev/null || true
    wait "$node_pid" 2>/dev/null || true
  fi
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill -TERM "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

show_daemon_diagnostics() {
  echo
  echo "Relevant daemon messages:"
  grep -Ei \
    "error|fail|reject|incompatible|did not advertise|QKD|QUIC|discovered peer" \
    "$daemon_log" | tail -n 25 || true
  echo "Complete daemon log: $daemon_log"
}

echo
if [[ "$reuse_existing_daemon" == "1" ]]; then
  printf 'Reused daemon PID %s in security mode %s\n' \
    "$existing_daemon_pid" "$mode" >"$daemon_log"
  ok "Existing daemon confirmed as security mode $mode"
else
  export AXON_DAEMON_PID_FILE="$pid_file"
  echo "== Starting AXON daemon =="
  echo "mode=$mode cipher=$AXON_QUIC_CIPHER domain=$ROS_DOMAIN_ID port=$test_port"
  "$daemon_path" --foreground --port "$test_port" --pid-file "$pid_file" \
    > >(tee "$daemon_log") 2>&1 &
  daemon_pid=$!

  started=0
  for _ in $(seq 1 100); do
    if grep -q "axon_daemon: security mode $mode" "$daemon_log" 2>/dev/null; then
      started=1
      break
    fi
    kill -0 "$daemon_pid" 2>/dev/null ||
      fail "axon_daemon exited during startup; inspect $daemon_log"
    sleep 0.1
  done
  [[ "$started" == "1" ]] ||
    fail "axon_daemon did not confirm mode $mode; inspect $daemon_log"

  ok "Daemon explicitly confirmed security mode $mode"
  if [[ "$mode" == "qkd" ]]; then
    grep -q "QKD mode enabled for SAE sae-${expected_role}" "$daemon_log" ||
      fail "Daemon did not confirm SAE $expected_role"
    ok "Daemon explicitly confirmed QKD with SAE $expected_role"
  fi
fi

if [[ "$action" == "startup" ]]; then
  echo
  echo "== STARTUP CHECK PASSED =="
  echo "Log: $daemon_log"
  exit 0
fi

if [[ "$action" == "demo" ]]; then
  duration="${AXON_TEST_DURATION:-12}"
elif [[ "$action" == "listener" ]]; then
  duration="${AXON_TEST_DURATION:-60}"
else
  duration="${AXON_TEST_DURATION:-20}"
fi
if ! [[ "$duration" =~ ^[0-9]+$ ]] || ((duration < 5)); then
  fail "AXON_TEST_DURATION must be at least 5 seconds"
fi

if [[ "$action" == "demo" ]]; then
  listener_log="$log_dir/listener.log"
  talker_log="$log_dir/talker.log"
  echo
  echo "== Running listener and talker together for ${duration}s =="
  set +e
  timeout --signal=INT --kill-after=3s "${duration}s" \
    ros2 run demo_nodes_cpp listener > >(tee "$listener_log") 2>&1 &
  node_pid=$!
  sleep 1
  timeout --signal=INT --kill-after=3s "${duration}s" \
    ros2 run demo_nodes_cpp talker > >(tee "$talker_log") 2>&1 &
  second_node_pid=$!
  wait "$second_node_pid"
  talker_rc=$?
  second_node_pid=""
  wait "$node_pid"
  listener_rc=$?
  node_pid=""
  set -e

  for result in "$listener_rc" "$talker_rc"; do
    if [[ "$result" != "0" && "$result" != "124" && "$result" != "130" ]]; then
      fail "A demo node exited with status $result; inspect $log_dir"
    fi
  done
  grep -q "Publishing:.*Hello World:" "$talker_log" ||
    fail "The local talker did not publish messages"
  grep -q "I heard: \\[Hello World:" "$listener_log" ||
    fail "The local listener did not receive messages"
  ok "Talker published and listener received ROS messages"
  echo
  echo "== LOCAL $mode TALKER/LISTENER DEMO PASSED =="
  if [[ "$mode" == "qkd" ]]; then
    echo "Note: same-host messages use shared memory; use two hosts to prove remote QKD/QUIC."
  fi
  echo "Listener log: $listener_log"
  echo "Talker log:   $talker_log"
  exit 0
fi

echo
echo "== Running ROS 2 $action for ${duration}s =="
echo "Start the opposite action on the other host now."
set +e
timeout --signal=INT --kill-after=3s "${duration}s" \
  ros2 run demo_nodes_cpp "$action" > >(tee "$node_log") 2>&1 &
node_pid=$!
wait "$node_pid"
node_rc=$?
node_pid=""
set -e
if [[ "$node_rc" != "0" && "$node_rc" != "124" && "$node_rc" != "130" ]]; then
  fail "demo_nodes_cpp $action exited with status $node_rc; inspect $node_log"
fi

sleep 1
if ! grep -q "discovered peer daemon" "$daemon_log"; then
  show_daemon_diagnostics
  fail "No remote AXON daemon was discovered"
fi
ok "Remote AXON daemon discovered"

if ! grep -Eq "QUIC connected to peer daemon|peer QUIC connection accepted" "$daemon_log"; then
  show_daemon_diagnostics
  fail "No successful daemon-to-daemon QUIC connection was observed"
fi
ok "Daemon-to-daemon QUIC connection established"

if [[ "$mode" == "qkd" ]]; then
  if ! grep -Eq "QKD session .* established|imported QKD key" "$daemon_log"; then
    show_daemon_diagnostics
    fail "No QKD key negotiation was observed"
  fi
  ok "QKD key was negotiated through the KME flow"
fi

if [[ "$action" == "listener" ]]; then
  grep -q "I heard: \\[Hello World:" "$node_log" ||
    fail "The listener did not receive remote ROS messages"
  ok "Listener received ROS messages from the remote host"
else
  grep -q "Publishing:.*Hello World:" "$node_log" ||
    fail "The talker did not publish ROS messages"
  ok "Talker published ROS messages; verify reception on the listener host"
fi

echo
echo "== END-TO-END $mode TEST PASSED =="
echo "Daemon log: $daemon_log"
echo "Node log:   $node_log"
