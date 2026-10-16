#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

architecture_test_project='tests/Fleetory.Architecture.Tests/Fleetory.Architecture.Tests.csproj'
persistence_test_project='tests/Fleetory.Persistence.Tests/Fleetory.Persistence.Tests.csproj'
artifact_root="$repo_root/artifacts/server"
windows_output="$artifact_root/win-x64"
linux_output="$artifact_root/linux-x64"
windows_archive="$artifact_root/Fleetory.Server-win-x64.zip"
linux_archive="$artifact_root/Fleetory.Server-linux-x64.tar.gz"

strict_build_status='NOT RUN'
tests_status='NOT RUN'
architecture_tests_status='NOT RUN'
postgresql_container_status='NOT RUN'
postgresql_connectivity_status='NOT RUN'
migrations_status='NOT RUN'
persistence_tests_status='NOT RUN'
health_ready_status='NOT RUN'
windows_publish_status='NOT RUN'
linux_publish_status='NOT RUN'
server_package_status='NOT RUN'
current_host_runtime_status='NOT RUN'
server_pid=''

summary() {
  printf '\nFleetory PHASE 6 verification summary\n'
  printf '%s\n' '------------------------------------'
  printf 'STRICT BUILD             %s\n' "$strict_build_status"
  printf 'TESTS                    %s\n' "$tests_status"
  printf 'ARCHITECTURE TESTS       %s\n' "$architecture_tests_status"
  printf 'POSTGRESQL CONTAINER     %s\n' "$postgresql_container_status"
  printf 'POSTGRESQL CONNECTIVITY  %s\n' "$postgresql_connectivity_status"
  printf 'MIGRATIONS               %s\n' "$migrations_status"
  printf 'PERSISTENCE TESTS        %s\n' "$persistence_tests_status"
  printf 'DATABASE READINESS       %s\n' "$health_ready_status"
  printf 'WINDOWS PUBLISH          %s\n' "$windows_publish_status"
  printf 'LINUX PUBLISH            %s\n' "$linux_publish_status"
  printf 'SERVER PACKAGE           %s\n' "$server_package_status"
  printf 'CURRENT HOST RUNTIME     %s\n' "$current_host_runtime_status"
}

cleanup() {
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

fail() {
  echo "$1" >&2
  summary
  exit 1
}

command -v dotnet >/dev/null 2>&1 || {
  strict_build_status='FAIL (.NET SDK missing)'
  summary
  exit 1
}

export DOTNET_CLI_UI_LANGUAGE='en-US'

external_test_connection_string="${FLEETORY_TEST_CONNECTION_STRING:-}"
using_external_test_database=false
if [[ -n "$external_test_connection_string" ]]; then
  using_external_test_database=true
  database_name="$(printf '%s' "$external_test_connection_string" | tr ';' '\n' | awk -F= 'tolower($1)=="database" {sub(/^[^=]*=/, ""); print; exit}')"
  [[ -n "$database_name" ]] || fail 'FLEETORY_TEST_CONNECTION_STRING must contain an explicit Database value.'
  printf '%s' "$database_name" | grep -qi 'test' || fail "FLEETORY_TEST_CONNECTION_STRING must target a test database whose name contains 'test'."
  case "${database_name,,}" in
    postgres|template0|template1) fail 'FLEETORY_TEST_CONNECTION_STRING targets a protected PostgreSQL database name.' ;;
  esac
  postgresql_container_status='NOT RUN (external override)'
else
  command -v docker >/dev/null 2>&1 || {
    postgresql_container_status='FAIL (Docker unavailable)'
    fail 'PostgreSQL integration verification requires Docker or an explicit FLEETORY_TEST_CONNECTION_STRING.'
  }
  if ! docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then
    postgresql_container_status='FAIL (Docker unavailable)'
    fail 'PostgreSQL integration verification requires Docker or an explicit FLEETORY_TEST_CONNECTION_STRING.'
  fi
  postgresql_container_status='READY (Docker available; Testcontainers will create PostgreSQL)'
fi

dotnet tool restore || { migrations_status='FAIL (tool restore)'; summary; exit 1; }
dotnet restore Fleetory.sln || { strict_build_status='FAIL (restore)'; summary; exit 1; }
dotnet build Fleetory.sln -c Release --no-restore || { strict_build_status='FAIL'; summary; exit 1; }
strict_build_status='PASS'

dotnet test Fleetory.sln -c Release --no-build --no-restore || { tests_status='FAIL'; summary; exit 1; }
tests_status='PASS'

dotnet test "$architecture_test_project" -c Release --no-build --no-restore || {
  architecture_tests_status='FAIL'; summary; exit 1;
}
architecture_tests_status='PASS'

dotnet test "$persistence_test_project" -c Release --no-build --no-restore || {
  [[ "$using_external_test_database" == true ]] || postgresql_container_status='FAIL'
  postgresql_connectivity_status='FAIL'
  migrations_status='FAIL'
  persistence_tests_status='FAIL'
  health_ready_status='FAIL'
  summary
  exit 1
}

[[ "$using_external_test_database" == true ]] || postgresql_container_status='PASS'
postgresql_connectivity_status='PASS'
migrations_status='PASS'
persistence_tests_status='PASS'
health_ready_status='PASS'

"$repo_root/eng/package-server.sh" --no-solution-restore || {
  windows_publish_status='FAIL'
  linux_publish_status='FAIL'
  server_package_status='FAIL'
  summary
  exit 1
}
windows_publish_status='PASS'
linux_publish_status='PASS'

validate_package() {
  local dir="$1"
  local rid="$2"
  local required=(
    'Fleetory.Server.dll'
    'Fleetory.Server.deps.json'
    'Fleetory.Server.runtimeconfig.json'
    'appsettings.json'
    'appsettings.Production.json'
    'Microsoft.EntityFrameworkCore.dll'
    'Microsoft.EntityFrameworkCore.Relational.dll'
    'Npgsql.dll'
    'Npgsql.EntityFrameworkCore.PostgreSQL.dll'
  )

  for file in "${required[@]}"; do
    [[ -f "$dir/$file" ]] || { echo "Package '$rid' is missing required runtime file '$file'." >&2; return 1; }
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

validate_package "$windows_output" win-x64 || fail 'Windows package content validation failed.'
validate_package "$linux_output" linux-x64 || fail 'Linux package content validation failed.'
[[ -s "$windows_archive" ]] || fail 'Windows ZIP package was not created or is empty.'
[[ -s "$linux_archive" ]] || fail 'Linux tar.gz package was not created or is empty.'
server_package_status='PASS'

case "$(uname -s)" in
  Linux)
    runtime_dir="$linux_output"
    runtime_name='Linux'
    ;;
  MINGW*|MSYS*|CYGWIN*)
    runtime_dir="$windows_output"
    runtime_name='Windows'
    ;;
  *)
    fail 'PHASE 6 published-server runtime smoke test is supported only on Windows or Linux.'
    ;;
esac

command -v curl >/dev/null 2>&1 || fail 'curl is required for the published-server smoke test.'

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
  port="${FLEETORY_PHASE6_SMOKE_PORT:-5089}"
fi

base_url="http://127.0.0.1:$port"
stdout_log="$artifact_root/phase6-smoke.stdout.log"
stderr_log="$artifact_root/phase6-smoke.stderr.log"
live_body_file="$artifact_root/phase6-live.body.txt"
rm -f "$stdout_log" "$stderr_log" "$live_body_file"
smoke_connection_string='Host=127.0.0.1;Port=1;Database=fleetory_test_package_smoke;Timeout=1;Command Timeout=1;Pooling=false'

(
  cd "$runtime_dir"
  ASPNETCORE_ENVIRONMENT=Production \
  FLEETORY_ConnectionStrings__Fleetory="$smoke_connection_string" \
  dotnet Fleetory.Server.dll --urls "$base_url" >"$stdout_log" 2>"$stderr_log"
) &
server_pid=$!

live_ok=false
for _ in $(seq 1 80); do
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo 'Published Fleetory.Server exited before becoming live.' >&2
    [[ -f "$stderr_log" ]] && cat "$stderr_log" >&2
    break
  fi
  if curl -fsS --max-time 2 "$base_url/health/live" >"$live_body_file" 2>/dev/null; then
    live_ok=true
    break
  fi
  sleep 0.25
done

[[ "$live_ok" == true ]] || fail 'Published Fleetory.Server did not pass /health/live within the timeout.'
[[ "$(tr -d '\r\n' <"$live_body_file")" == 'Healthy' ]] || fail '/health/live did not return Healthy.'

correlation_id='phase6-published-smoke'
actual_correlation_id="$(curl -fsS -D - -o /dev/null --max-time 5 \
  -H "X-Correlation-ID: $correlation_id" "$base_url/health/live" \
  | tr -d '\r' | awk -F': ' 'tolower($1)=="x-correlation-id" {print $2}' | tail -n 1)"
[[ "$actual_correlation_id" == "$correlation_id" ]] || fail 'CorrelationId response mismatch in published-server smoke test.'

kill -TERM "$server_pid"
wait "$server_pid" || true
server_pid=''
current_host_runtime_status="PASS ($runtime_name)"

summary

if [[ "$using_external_test_database" == true ]]; then
  echo 'External PostgreSQL verification passed, but PHASE 6 completion still requires the default disposable Testcontainers PostgreSQL run.' >&2
  exit 2
fi
