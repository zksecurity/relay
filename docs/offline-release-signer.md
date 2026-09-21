# Offline release-signer handoff

Use the same approved Relay release on every role machine. Install the release
signer images before disconnecting the signer. Keep the signer workspace and
private key on that machine; it does not need AWS or R2 credentials.

1. Complete the ordinary release-signer identity, coordinator-key verification,
   and signed enrollment preparation. Transfer only the public enrollment and
   disclosure to the coordinator. Preserve the prepared directory layout.
2. In coordinator operations, choose **I — Import the offline signer's public
   enrollment** when that enrollment is pending. Review its assigned identity and
   confirm `VERIFY AND RECORD ENROLLMENT`.
3. After both phases, both beacons, finalization, and coordinator review, choose
   **E — Export authenticated public snapshot for the offline signer**. Select
   a fresh directory inside the coordinator workspace. Transfer that exported
   directory to the signer; authenticate the coordinator key separately.
4. Open the signer's ordinary ceremony guide and select the transferred snapshot
   directory. The guide verifies its signed history and retained progress without
   fetching storage. Review and sign the package. An offline snapshot cannot prove
   the latest online state; the coordinator checks the returned package against
   its frozen review.
5. Transfer only the completed public release-package directory back into the
   coordinator workspace. Leave the signer's key and profile on the signer host.
6. Create the release upload grant in coordinator operations, then choose
   **U — Upload the offline signer's returned public release package**. Select
   the returned directory and the grant. Continue with the ordinary inbox check
   and release verification/recording action.

The signer may remain unavailable between these handoffs. The ceremony waits for
its enrollment or signature; operators must resume the relevant guide when the
public files are ready. No automatic signing or prompt approval is implied.

After completion, use `relay audit export` on each role and `relay audit combine`
on the coordinator to collect recorded activity and explicit coverage gaps.
