#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command '$1' was not found on PATH." >&2
    exit 1
  fi
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Required environment variable '$name' is not set." >&2
    exit 1
  fi
}

require_command dotnet
require_env SONAR_HOST_URL
require_env SONAR_PROJECT_KEY
require_env SONAR_TOKEN

sonar_organization="${SONAR_ORGANIZATION:-}"
sonar_host="${SONAR_HOST_URL#*://}"
sonar_host="${sonar_host%%/*}"
sonar_host="${sonar_host%%:*}"
if [[ "$sonar_host" == 'sonarcloud.io' || "$sonar_host" == *.sonarcloud.io ]]; then
  [[ -n "$sonar_organization" ]] || {
    echo 'SONAR_ORGANIZATION is required when SONAR_HOST_URL points to SonarQube Cloud.' >&2
    exit 1
  }
fi

quality_gate_timeout="${SONAR_QUALITYGATE_TIMEOUT:-300}"
if ! [[ "$quality_gate_timeout" =~ ^[1-9][0-9]*$ ]]; then
  echo "SONAR_QUALITYGATE_TIMEOUT must be a positive integer number of seconds." >&2
  exit 1
fi

coverage_relative_path="artifacts/coverage/coverage.xml"
coverage_path="$repo_root/$coverage_relative_path"

# The token is never echoed by this script. Do not enable shell tracing here.
dotnet tool restore

rm -rf "$repo_root/artifacts/coverage" "$repo_root/.sonarqube"
mkdir -p "$repo_root/artifacts/coverage"

dotnet clean Fleetory.sln -c Release --nologo

begin_args=(
  tool run dotnet-sonarscanner --allow-roll-forward -- begin
  "/k:${SONAR_PROJECT_KEY}"
  "/d:sonar.host.url=${SONAR_HOST_URL}"
  "/d:sonar.token=${SONAR_TOKEN}"
  "/d:sonar.cs.vscoveragexml.reportsPaths=${coverage_relative_path}"
  "/d:sonar.coverage.exclusions=eng/**,tests/Fleetory.Tools.Tests/**"
  "/d:sonar.qualitygate.wait=true"
  "/d:sonar.qualitygate.timeout=${quality_gate_timeout}"
  "/d:sonar.exclusions=**/bin/**,**/obj/**,artifacts/**,.sonarqube/**"
)

if [[ -n "$sonar_organization" ]]; then
  begin_args+=("/o:${sonar_organization}")
fi

if [[ -n "${SONAR_PROJECT_NAME:-}" ]]; then
  begin_args+=("/n:${SONAR_PROJECT_NAME}")
fi

dotnet "${begin_args[@]}"

dotnet build Fleetory.sln -c Release --no-incremental --disable-build-servers

test_command='dotnet test Fleetory.sln -c Release --no-build --no-restore'
dotnet tool run dotnet-coverage --allow-roll-forward -- collect \
  "$test_command" \
  -f xml \
  -o "$coverage_path"

if [[ ! -s "$coverage_path" ]]; then
  echo "Coverage report was not created or is empty: $coverage_path" >&2
  exit 1
fi

dotnet tool run dotnet-sonarscanner --allow-roll-forward -- end \
  "/d:sonar.token=${SONAR_TOKEN}"

echo 'SONAR ANALYSIS      PASS'
echo 'SONAR QUALITY GATE  PASS'
