#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
server_project="$repo_root/src/Fleetory.Server/Fleetory.Server.csproj"
artifact_root="$repo_root/artifacts/server"
windows_output="$artifact_root/win-x64"
linux_output="$artifact_root/linux-x64"
windows_archive="$artifact_root/Fleetory.Server-win-x64.zip"
linux_archive="$artifact_root/Fleetory.Server-linux-x64.tar.gz"
skip_solution_restore=false

if [[ "${1:-}" == "--no-solution-restore" ]]; then
  skip_solution_restore=true
elif [[ $# -gt 0 ]]; then
  echo "Unknown argument: $1" >&2
  exit 2
fi

command -v dotnet >/dev/null 2>&1 || { echo '.NET SDK was not found on PATH.' >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "The 'tar' command is required." >&2; exit 1; }
command -v zip >/dev/null 2>&1 || { echo "The 'zip' command is required." >&2; exit 1; }

rm -rf "$artifact_root"
mkdir -p "$windows_output" "$linux_output"

cd "$repo_root"

if [[ "$skip_solution_restore" != true ]]; then
  dotnet restore Fleetory.sln
fi

dotnet restore "$server_project" -r win-x64
dotnet publish "$server_project" \
  -c Release \
  -r win-x64 \
  --self-contained false \
  -p:UseAppHost=false \
  --no-restore \
  -o "$windows_output"

dotnet restore "$server_project" -r linux-x64
dotnet publish "$server_project" \
  -c Release \
  -r linux-x64 \
  --self-contained false \
  -p:UseAppHost=false \
  --no-restore \
  -o "$linux_output"

(
  cd "$windows_output"
  zip -qr "$windows_archive" .
)
tar -czf "$linux_archive" -C "$linux_output" .

cat <<SUMMARY

Fleetory Server packaging summary
---------------------------------
WINDOWS PUBLISH  PASS  $windows_output
LINUX PUBLISH    PASS  $linux_output
WINDOWS PACKAGE  PASS  $windows_archive
LINUX PACKAGE    PASS  $linux_archive
DEPLOYMENT MODEL framework-dependent (.NET 10 runtime required)
SUMMARY
