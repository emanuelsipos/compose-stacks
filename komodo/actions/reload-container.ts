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

function optionalSignal() {
  const value = ARGS.signal === undefined || ARGS.signal === null || ARGS.signal === "" ? "HUP" : String(ARGS.signal);
  if (!/^[A-Za-z][A-Za-z0-9]*$/.test(value)) {
    throw new Error("Action argument is not a valid signal name: signal");
  }
  return value;
}

function optionalMode() {
  const value = ARGS.mode === undefined || ARGS.mode === null || ARGS.mode === "" ? "signal" : String(ARGS.mode);
  if (value !== "signal" && value !== "restart") {
    throw new Error("Action argument must be signal or restart: mode");
  }
  return value;
}

function optionalBoolean(name, defaultValue) {
  const value = ARGS[name];
  if (value === undefined || value === null || value === "") {
    return defaultValue;
  }
  if (value === true || value === "true") {
    return true;
  }
  if (value === false || value === "false") {
    return false;
  }
  throw new Error(`Action argument must be true or false: ${name}`);
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

const server = requiredString("server");
const container = containerName("container");
const mode = optionalMode();
const signal = optionalSignal();
const fallbackRestart = optionalBoolean("fallback_restart", true) ? "1" : "0";

const command = `set -u
container=${shellQuote(container)}
mode=${shellQuote(mode)}
signal=${shellQuote(signal)}
fallback_restart=${shellQuote(fallbackRestart)}

status() {
  printf '%s\\n' "reload-container: $1"
}

fail() {
  status "failed: $1"
  return 1
}

main() {
  command -v docker >/dev/null 2>&1 || { fail 'docker is unavailable'; return; }
  docker container inspect "$container" >/dev/null 2>&1 || { fail 'container does not exist'; return; }

  running=$(docker container inspect -f '{{.State.Running}}' "$container" 2>/dev/null) || { fail 'cannot inspect container state'; return; }
  [ "$running" = true ] || { fail 'container is not running'; return; }

  if [ "$mode" = restart ]; then
    status 'restarting container'
    docker restart "$container" >/dev/null 2>&1 || { fail 'container restart failed'; return; }
    sleep 1
    running=$(docker container inspect -f '{{.State.Running}}' "$container" 2>/dev/null) || { fail 'cannot inspect container state after restart'; return; }
    [ "$running" = true ] || { fail 'container is not running after restart'; return; }
    status 'container running'
    return 0
  fi

  signal_rc=0
  docker kill --signal "$signal" "$container" >/dev/null 2>&1 || signal_rc=$?
  sleep 1
  running=$(docker container inspect -f '{{.State.Running}}' "$container" 2>/dev/null) || { fail 'cannot inspect container state after signal'; return; }

  if [ "$signal_rc" -eq 0 ] && [ "$running" = true ]; then
    status 'signal delivered'
    return 0
  fi

  [ "$fallback_restart" = 1 ] || { fail 'signal did not leave container running'; return; }
  status 'restarting container'
  docker restart "$container" >/dev/null 2>&1 || { fail 'container restart failed'; return; }
  sleep 1
  running=$(docker container inspect -f '{{.State.Running}}' "$container" 2>/dev/null) || { fail 'cannot inspect container state after restart'; return; }
  [ "$running" = true ] || { fail 'container is not running after restart'; return; }
  status 'container running'
}

main
result=$?
(exit "$result")`;

const terminal = `reload-container-${container}`;
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
      if (message.startsWith("reload-container:")) {
        console.log(message);
      }
    },
    onFinish: (exitCode) => {
      terminalExitCode = String(exitCode);
    },
  },
);

if (terminalExitCode !== "0") {
  throw new Error("Container reload Action failed; inspect concise terminal status.");
}
