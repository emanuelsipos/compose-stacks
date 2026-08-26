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
  return 1
}

output_file=
cleanup() {
  [ -z "$output_file" ] || rm -f "$output_file"
}

main() {
  command -v docker >/dev/null 2>&1 || { fail 'docker is unavailable'; return; }
  command -v grep >/dev/null 2>&1 || { fail 'grep is unavailable'; return; }
  command -v mktemp >/dev/null 2>&1 || { fail 'mktemp is unavailable'; return; }
  command -v timeout >/dev/null 2>&1 || { fail 'timeout is unavailable'; return; }
  docker container inspect "$container" >/dev/null 2>&1 || { fail 'container does not exist'; return; }

  output_file=$(mktemp) || { fail 'cannot create temporary output file'; return; }

  running=$(docker container inspect -f '{{.State.Running}}' "$container" 2>/dev/null) || { fail 'cannot inspect container state'; return; }
  [ "$running" = false ] || { fail 'container is already running'; return; }

  status 'starting container'
  start_rc=0
  timeout "$timeout_seconds"s docker start -a "$container" >"$output_file" 2>&1 || start_rc=$?

  if [ "$start_rc" -ne 0 ]; then
    running=$(docker container inspect -f '{{.State.Running}}' "$container" 2>/dev/null) || { fail 'cannot inspect container after failed start'; return; }
    if [ "$running" = true ]; then
      timeout 15s docker stop "$container" >/dev/null 2>&1 || true
    fi
    if [ "$start_rc" -eq 124 ]; then
      fail 'container timed out'
      return
    fi
  fi

  state=$(docker container inspect -f '{{.State.Status}}' "$container" 2>/dev/null) || { fail 'cannot inspect final container state'; return; }
  exit_code=$(docker container inspect -f '{{.State.ExitCode}}' "$container" 2>/dev/null) || { fail 'cannot inspect final container exit code'; return; }
  [ "$state" = exited ] || { fail 'container did not exit'; return; }
  [ "$exit_code" = 0 ] || { fail 'container exited nonzero'; return; }
  [ "$start_rc" -eq 0 ] || { fail 'container start command failed'; return; }
  if grep -q 'komodo-deploy-hook:' "$output_file" && \
    grep 'komodo-deploy-hook:' "$output_file" | \
      grep -qv 'komodo-deploy-hook: reload requested$'; then
    fail 'deploy hook reported failure'
    return
  fi
  status 'completed successfully'
}

trap cleanup HUP INT TERM
main
result=$?
cleanup
trap - HUP INT TERM
(exit "$result")`;

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
