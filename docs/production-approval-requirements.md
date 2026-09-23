# Production approval gates

New coordinator-replay ceremonies use definition v5 and decision v4. They do not
require participant independence or a live twenty-party ceremony as approval gates.
There are no setup toggles for these removed gates. Historical signed ceremonies
retain their original validation. Other release and production checks still apply.
Multiple identities controlled by one operator do not establish independence.

Relay pins the compatible proof-tool release at commit
`57fecbf6eec76e30e0e4e487242293320d64349b`.
For production-mode ceremonies, a verified GO decision binds the exact signed
circuit and release. The tiny and K11 test circuits may receive GO for their own
ceremony, but their keys do not prove ownership.
Tessera setup contracts remain unchanged.
