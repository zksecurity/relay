# Practical CLI upgrades (reviewed implementation plan)

Status: implementation draft; end-to-end validation pending. This document does not approve any transition or change a ceremony.

## Operator workflow

The initial scope is coordinator updates between completed operations. Other roles retain their existing qualified paths.

`relay ceremony upgrade` authenticates the requested published release and records the operator's selection. It must not require a separately published approval release. Compatibility runs remain evidence, not permission: missing evidence is shown as untested, failures as failures, and neither is rewritten into a passing report. The selection records exact source/target application hashes and immutable runtime images.

Existing qualified selections remain readable and retain their original evidence. New operator-selected transitions use a distinct record discriminator so old readers reject rather than misinterpret them as qualified transitions. Reopening and repairing an interrupted installer validate the durable selection and retained bindings. An old executable is not promised to support returning to an operator-selected transition; recovery must use the selected released executable.

## Checks that remain mandatory

Authenticate the original and target published assets with existing attestation verification, and match the running executable to the attested target. Preserve the original signed definition, identities, signing image and contributor image. Measure proof-tool in each relevant image and compare against the signed ceremony pin. Reject unsupported protocols or retained operation formats. Keep workspace/related-profile locks, container exclusion, before/after inventory comparison, atomic selection installation and installer recovery. Do not recompute, sign, publish, delete recovery records, or rewrite frozen profiles to admit an upgrade.

Compatibility evidence must not gate selection or weaken these checks. Do not create synthetic qualification reports, fake qualification digests, or claim safe predecessor coverage that was never tested.

## Initial publication followed by failed refresh

The current coordinator successfully published its sequence-zero checkpoint but cannot complete its first refresh because the old downloader times out. It has no high-water anchor. Initial publication does not write a workflow CAS journal, so requiring that journal would leave the same deadlock.

For this exact missing-anchor case, retrieve the current root using the configured authenticated provider, authenticate its referenced signed checkpoint using the original pinned proof-tool, and bind the complete checkpoint/signature references to the locally retained initial checkpoint. Require sequence zero, no predecessor, original coordinator first hop and no unresolved action. Validate all required local artifacts and existing inventory checks. Recheck the remote root before committing selection and reject a changed root. Do not fabricate a high-water record. An existing corrupt, symlinked, unreadable or conflicting anchor must fail instead of taking the missing-anchor path. A local signed checkpoint or upload memo alone is insufficient evidence of publication.

## Validation

Cover untested operator selection, exact asset verification failure, changed proof pin, identity/runtime mismatch, tampered selection, reopening and installer repair, preserved historical qualified selections, and retained-file equality. Exercise the real initial-publication layout with no CAS journal: matching authenticated remote root succeeds; missing root, local-only proposal, changed root, wrong ceremony/reference/signature/size, nonzero sequence, corrupt existing anchor and unfinished action fail. Run the released continuation/retry/recovery journeys and actual large-circuit refresh without treating their results as a permission service.

## Independent review

An independent read-only review of upgrade admission and initial publication found that initial publication has no completed CAS journal, and that a new host executable cannot open the old guide directly because release admission occurs before V4 routing. The plan incorporates both findings. Review was not execution of tests and changed no production state.
