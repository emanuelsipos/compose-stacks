function requiredString(name) {
  const value = ARGS[name];
  if (typeof value !== "string" || value.trim() === "" || /[^\x20-\x7e]/.test(value)) {
    throw new Error(`Missing or invalid Action argument: ${name}`);
  }
  return value;
}

function containerName(name) {
  const value = requiredString(name);
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(value)) {
    throw new Error(`Action argument is not a valid container name: ${name}`);
  }
  return value;
}

function positiveInteger(name, defaultValue, maximum) {
  const value = ARGS[name];
  const normalized = value === undefined || value === null || value === "" ? defaultValue : String(value);
  if (!/^[1-9][0-9]*$/.test(normalized)) {
    throw new Error(`Action argument must be a positive integer: ${name}`);
  }
  const parsed = Number(normalized);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) {
    throw new Error(`Action argument is out of range: ${name}`);
  }
  return normalized;
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

const server = requiredString("server");
const container = containerName("container");
const timeoutSeconds = positiveInteger("timeout_seconds", "900", 86400);

const command = `set -u
container=${shellQuote(container)}
timeout_seconds=${shellQuote(timeoutSeconds)}
umask 077

status() {
  printf '%s\\n' "run-one-shot: $1"
}

fail() {
  status "failed: $1"
  exit 1
}

command -v docker >/dev/null 2>&1 || fail 'docker is unavailable'
command -v grep >/dev/null 2>&1 || fail 'grep is unavailable'
command -v mktemp >/dev/null 2>&1 || fail 'mktemp is unavailable'
command -v timeout >/dev/null 2>&1 || fail 'timeout is unavailable'
docker container inspect "$container" >/dev/null 2>&1 || fail 'container does not exist'

output_file=$(mktemp) || fail 'cannot create temporary output file'
cleanup() {
  rm -f "$output_file"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

running=$(docker container inspect -f '{{.State.Running}}' "$container" 2>/dev/null) || fail 'cannot inspect container state'
[ "$running" = false ] || fail 'container is already running'

status 'starting container'
start_rc=0
timeout "$timeout_seconds"s docker start -a "$container" >"$output_file" 2>&1 || start_rc=$?

if [ "$start_rc" -ne 0 ]; then
  running=$(docker container inspect -f '{{.State.Running}}' "$container" 2>/dev/null) || fail 'cannot inspect container after failed start'
  if [ "$running" = true ]; then
    timeout 15s docker stop "$container" >/dev/null 2>&1 || true
  fi
  [ "$start_rc" -eq 124 ] && fail 'container timed out'
fi

state=$(docker container inspect -f '{{.State.Status}}' "$container" 2>/dev/null) || fail 'cannot inspect final container state'
exit_code=$(docker container inspect -f '{{.State.ExitCode}}' "$container" 2>/dev/null) || fail 'cannot inspect final container exit code'
[ "$state" = exited ] || fail 'container did not exit'
[ "$exit_code" = 0 ] || fail 'container exited nonzero'
[ "$start_rc" -eq 0 ] || fail 'container start command failed'
if grep -q 'komodo-deploy-hook:' "$output_file" && \
  ! grep -q 'komodo-deploy-hook: reload requested' "$output_file"; then
  fail 'deploy hook reported failure'
fi
status 'completed successfully'`;

const terminal = `run-one-shot-container-${container}`;
let terminalExitCode;

await komodo.execute_server_terminal(
  {
    server,
    terminal,
    command,
    init: {
      command: "sh",
      recreate: Types.TerminalRecreateMode.Never,
    },
  },
  {
    onLine: (line) => {
      const message = String(line).trim();
      if (message.startsWith("run-one-shot:")) {
        console.log(message);
      }
    },
    onFinish: (exitCode) => {
      terminalExitCode = String(exitCode);
    },
  },
);

if (terminalExitCode !== "0") {
  throw new Error("One-shot container Action failed; inspect concise terminal status.");
}
