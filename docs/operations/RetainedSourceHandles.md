# Retained public source handles

The retained service admission peer holds ordinary, single-link public source
files and their directories before capturing the four input packets. It binds
identity, size, hash and mtime, retaining descriptor and pathname ctime views
independently. Every live check verifies those handles and re-enumerates the
fixed source namespace. A changed or additional source refuses admission with
a bounded typed frame before further native work.

The catalog uses the existing HistoricalAuditInputPins source hashes. Its
namespace is eng/src, eight active root build inputs and ten literal runtime
helpers; build/cache directories are excluded. Wire metadata cannot choose a
root, command or extra source. The source plan has a 448-file/8-MiB ceiling.
The peer response and final receipt bind its exact plan hash and file count.
The default code snapshot digest and schema remain unchanged when optional
source pins are requested.

On generated Windows data, normal Server/PostgreSQL/immudb execution passed
with 415 held files and 223 live checks. Owner loss and original admission
expiry passed with 55 checks each and their own cleanup. Linux source-handle
and catalog tests passed 14/14 and 6/6. These prototype results are separate
from commit qualification; required CI runs both source test suites on both OS.

This is a held source-set boundary, not complete execution authentication.
The set excludes bytecode caches, external SDK/runtime/package inputs and
commands; the image build happens before this admission lease. Source origin,
full transitive execution, original-purpose executor readiness, coordinated
original recovery and Phase 7 completion remain unverified. No original
archives or existing secrets/private PKI were read for this validation.

A prior interrupted attempt left one fixture image after its four recorded
containers disappeared. That observation is not complete cleanup and does not
grant a new process authority to adopt or delete the image. All three fresh
runs reported cleanup and their recorded container/image IDs were independently
absent. General creator/daemon/host-loss recovery remains open.
