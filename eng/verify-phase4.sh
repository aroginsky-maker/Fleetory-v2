#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

dotnet restore Fleetory.sln
dotnet build Fleetory.sln -c Release --no-restore
dotnet test Fleetory.sln -c Release --no-build --no-restore
