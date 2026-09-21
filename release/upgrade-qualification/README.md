# Reviewed local update qualification

Initially empty: no update pair is approved.

After publishing target B with compatible-update support, test those exact
published executables locally using the three-scenario qualification runner.
Submit its sanitized report here, named with the declaration's `AssetName()`,
and its exact pair in `../upgrade-policy-v2.json` for protected-main review.
Do not submit private requests, credentials, fixture paths or raw logs.

The later approval release C authenticates B's original published binary and
every predecessor binary against report hashes. It publishes only the approval
and report, not replacement B binaries. CI provenance attests approval of reviewed
local evidence; it does not claim the Mac tests ran in CI.

Operators install B and specify `--release role-images-B --approval-release
role-images-C`. B must already support this option and saved selection format.
Do not approve older apps that cannot read that format. See
[qualification](../../docs/maintainer/ceremony-upgrade-qualification.md).
