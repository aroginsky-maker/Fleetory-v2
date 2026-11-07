#!/bin/sh
set -eu
signer_address="$(hostname -i)"
case "$signer_address" in
  ""|*" "*) echo "Signer container requires one explicit IP address." >&2; exit 1 ;;
esac
exec dotnet /app/Fleetory.CommandSigner.Host.dll "$@" --Signer:BindAddress="$signer_address"
