# Current Sonar metrics

`eng/report-sonar-metrics.ps1` is informational. It never accepts a quality gate
or changes the required CI result. If current evidence is unavailable it prints
`SONAR METRICS NOT AVAILABLE`; it does not use a previous PR analysis as a fallback.

The existing official issue gate still requires the exact PR head or push
revision, the SonarQube Cloud application, a fresh successful check, the correct
project/scope, and zero new/accepted issues. Only after those checks does it write
the generated `.sonarqube/out/.sonar/fleetory-verified-submission.json` cache.
The cache binds the submission file hash, task, revision, scope, check, completion
time and GitHub run/attempt. Starting the gate removes a prior generated cache;
any refused gate leaves no success cache. These files are local CI metadata,
not external custody, approval or a substitute for the official check.

The report validates this canonical bounded cache against the current GitHub
event/run/attempt and bounded submission file before making requests. Requests
use the existing Sonar token only at `https://sonarcloud.io`, with TLS validation,
no redirects and a 15-second timeout. It requires the exact task/project to be
successfully processed with an analysis ID. The component's latest task must
match and its queue must be empty. It then buffers the requested PR/branch
percentages and optional per-file diagnostics. Task, latest-task/queue and local
submission bindings are rechecked before any buffered percentage is printed.
A changed or competing analysis, failed/pending/cancelled processing, malformed
values, missing access or API failure discards the buffer. Raw transport error
text and authorization values are never logged.

The output identifies the verified revision, check, task and analysis ID. Main
and feature branches use their actual branch selector. A missing percentage is
reported as unavailable; optional file diagnostics may fail without inventing
file metrics. The endpoint returns latest component measures rather than a
historical per-analysis snapshot, so changes during the sample are refused.
This is trusted CI correlation, not protection against an arbitrary same-user
process rewriting local evidence or a different analysis changing and reverting
outside the observation interval.

`tests/Fleetory.Tooling.Tests/SonarIssueGate.Tests.ps1` retains its existing gate
tests and runs 49 generated report CLI cases with intercepted network calls.
They cover PR/main/feature success, supported period formats, missing or changed
receipts/submissions, wrong revision/run/attempt/scope, incomplete or failed
processing, competing/newer tasks, changes after a metrics read, invalid values,
and transport errors containing a fake token. No original data or credential is
used. These tests do not prove the availability or cause of an external service
failure. Local Sonar and native .NET coverage remain separate evidence from
official SonarCloud; Phase 7 and PR acceptance stay open when official evidence
is missing.

API references: [SonarQube Cloud Web API](https://docs.sonarsource.com/sonarqube-cloud/appendices/web-api)
and the [SonarSource component-task API implementation](https://github.com/SonarSource/sonarqube/blob/master/server/sonar-webserver-webapi/src/main/java/org/sonar/server/ce/ws/ComponentAction.java).
