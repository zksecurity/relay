# Legacy three-machine tiny rehearsal

This is a developer rehearsal using direct CLI scripts and test identities.
It is not the normal Docker operator setup or a production procedure.

Follow the stages in order:
1. [Install the legacy kit](INSTALL.md).
2. [Prepare the three machines](prepare.md).
3. [Run Phase 1](phase1.md).
4. [Run Phase 2, synchronization, and optional evidence tests](phase2.md).

The phase pages retain the original numbered steps for existing script users.
Only the optional evidence-upload fixture test needs proof-tool source and Go.
Use fresh directories and test identities; do not reuse production keys.

For an actual role assignment, use the [operator guides](../../docs/README.md).
Provisioning guides: [AWS](../../docs/maintainer/aws.md),
[R2](../../docs/maintainer/r2-rehearsal.md).
Downloaded legacy bundles retain those paths inside their package.

This exercise does not by itself establish independent human operators,
independent mirrors, or production signing authorization.
