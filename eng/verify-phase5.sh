#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="$repo_root/artifacts/server"
windows_output="$artifact_root/win-x64"
linux_output="$artifact_root/linux-x64"
windows_archive="$artifact_root/Fleetory.Server-win-x64.zip"
linux_archive="$artifact_root/Fleetory.Server-linux-x64.tar.gz"

strict_status='NOT RUN'
tests_status='NOT RUN'
architecture_status='NOT RUN'
windows_publish_status='NOT RUN'
linux_publish_status='NOT RUN'
windows_runtime_status='NOT VERIFIED'
linux_runtime_status='NOT VERIFIED'
health_status='NOT RUN'
correlation_status='NOT RUN'
server_pid=''

summary() {
  cat <<SUMMARY

Fleetory PHASE 5 verification summary
------------------------------------
STRICT BUILD        $strict_status
TESTS               $tests_status
ARCHITECTURE TESTS  $architecture_status
WINDOWS PUBLISH     $windows_publish_status
LINUX PUBLISH       $linux_publish_status
WINDOWS RUNTIME     $windows_runtime_status
LINUX RUNTIME       $linux_runtime_status
HEALTH TESTS        $health_status
CORRELATION ID      $correlation_status
SUMMARY
}

cleanup() {
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

command -v dotnet >/dev/null 2>&1 || { strict_status='FAIL (.NET SDK missing)'; summary; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "The 'curl' command is required for published-server smoke tests." >&2; exit 1; }

cd "$repo_root"

dotnet restore Fleetory.sln || { strict_status='FAIL (restore)'; summary; exit 1; }
dotnet build Fleetory.sln -c Release --no-restore || { strict_status='FAIL'; summary; exit 1; }
strict_status='PASS'

dotnet test Fleetory.sln -c Release --no-build --no-restore || { tests_status='FAIL'; summary; exit 1; }
tests_status='PASS'

dotnet test tests/Fleetory.Architecture.Tests/Fleetory.Architecture.Tests.csproj \
  -c Release --no-build --no-restore || { architecture_status='FAIL'; summary; exit 1; }
architecture_status='PASS'

"$repo_root/eng/package-server.sh" --no-solution-restore || {
  windows_publish_status='FAIL'
  linux_publish_status='FAIL'
  summary
  exit 1
}
windows_publish_status='PASS'
linux_publish_status='PASS'

validate_package() {
  local dir="$1"
  local rid="$2"
  local required=(
    Fleetory.Server.dll
    Fleetory.Server.deps.json
    Fleetory.Server.runtimeconfig.json
    appsettings.json
    appsettings.Production.json
  )

  for file in "${required[@]}"; do
    [[ -f "$dir/$file" ]] || { echo "Package '$rid' is missing '$file'." >&2; return 1; }
  done

  [[ ! -f "$dir/appsettings.Development.json" ]] || {
    echo "Package '$rid' must not contain appsettings.Development.json." >&2
    return 1
  }

  if find "$dir" -type f \( \
      -name '*.cs' -o -name '*.csproj' -o -name '*.sln' -o \
      -name '*.Tests.dll' -o -name '*.Tests.pdb' -o -name '*.user' -o -name '*.suo' \
    \) -print -quit | grep -q .; then
    echo "Package '$rid' contains source/test/developer artifacts." >&2
    return 1
  fi

  if grep -RniE --include='*.json' '"(password|secret|token|api[_-]?key|connectionstrings?)"[[:space:]]*:' "$dir" >/dev/null 2>&1; then
    echo "Package '$rid' contains a secret-like configuration key." >&2
    return 1
  fi
}

validate_package "$windows_output" win-x64 || { windows_publish_status='FAIL (package validation)'; summary; exit 1; }
validate_package "$linux_output" linux-x64 || { linux_publish_status='FAIL (package validation)'; summary; exit 1; }
[[ -s "$windows_archive" ]] || { windows_publish_status='FAIL (archive missing)'; summary; exit 1; }
[[ -s "$linux_archive" ]] || { linux_publish_status='FAIL (archive missing)'; summary; exit 1; }

case "$(uname -s)" in
  Linux)
    runtime_dir="$linux_output"
    runtime_kind='linux'
    ;;
  MINGW*|MSYS*|CYGWIN*)
    runtime_dir="$windows_output"
    runtime_kind='windows'
    ;;
  *)
    echo 'PHASE 5 server runtime smoke test is supported only on Windows or Linux.' >&2
    summary
    exit 1
    ;;
esac

if command -v python3 >/dev/null 2>&1; then
  port="$(python3 - <<'PYPORT'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PYPORT
)"
else
  port="${FLEETORY_PHASE5_SMOKE_PORT:-5088}"
fi
base_url="http://127.0.0.1:$port"
stdout_log="$artifact_root/phase5-smoke.stdout.log"
stderr_log="$artifact_root/phase5-smoke.stderr.log"
live_body_file="$artifact_root/phase5-live.body.txt"
rm -f "$stdout_log" "$stderr_log" "$live_body_file"

(
  cd "$runtime_dir"
  ASPNETCORE_ENVIRONMENT=Production dotnet Fleetory.Server.dll --urls "$base_url" \
    >"$stdout_log" 2>"$stderr_log"
) &
server_pid=$!

live_ok=false
for _ in $(seq 1 80); do
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo 'Published Fleetory.Server exited before becoming healthy.' >&2
    [[ -f "$stderr_log" ]] && cat "$stderr_log" >&2
    break
  fi
  if curl -fsS --max-time 2 "$base_url/health/live" >"$live_body_file" 2>/dev/null; then
    live_ok=true
    break
  fi
  sleep 0.25
done

if [[ "$live_ok" != true ]]; then
  [[ "$runtime_kind" == 'linux' ]] && linux_runtime_status='FAIL' || windows_runtime_status='FAIL'
  summary
  exit 1
fi

[[ "$(tr -d '\r\n' <"$live_body_file")" == 'Healthy' ]] || { health_status='FAIL'; summary; exit 1; }
[[ "$(curl -fsS --max-time 5 "$base_url/health/ready" | tr -d '\r\n')" == 'Healthy' ]] || { health_status='FAIL'; summary; exit 1; }
health_status='PASS'

correlation_id='phase5-published-smoke'
actual_correlation_id="$(curl -fsS -D - -o /dev/null --max-time 5 \
  -H "X-Correlation-ID: $correlation_id" "$base_url/health/live" \
  | tr -d '\r' | awk -F': ' 'tolower($1)=="x-correlation-id" {print $2}' | tail -n 1)"
[[ "$actual_correlation_id" == "$correlation_id" ]] || { correlation_status='FAIL'; summary; exit 1; }
correlation_status='PASS'

if [[ "$runtime_kind" == 'linux' ]]; then
  linux_runtime_status='PASS'
  windows_runtime_status='NOT VERIFIED (cross-publish only)'
else
  windows_runtime_status='PASS'
  linux_runtime_status='NOT VERIFIED (cross-publish only)'
fi

# SIGTERM exercises the normal Generic Host shutdown path on Linux.
kill -TERM "$server_pid"
wait "$server_pid" || true
server_pid=''

summary
