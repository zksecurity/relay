-------------------------- MODULE Onboarding --------------------------
EXTENDS TLC
CONSTANT Broken
VARIABLE s
vars == <<s>>

\* One coordinator and participant; prior identity/definition setup assumed.
\* Strings represent exact artifact identities, not filenames alone.
Init == s = [enrolled |-> FALSE, explainedSend |-> FALSE,
             sent |-> FALSE, enrollmentReceived |-> FALSE,
             askedStorage |-> FALSE, available |-> FALSE,
             delivered |-> "none", imported |-> "none",
             verified |-> "none", profile |-> "none"]

Recommend == IF ~s.enrolled THEN "sign-enrollment"
             ELSE IF Broken THEN "create-profile"
             ELSE IF ~s.sent THEN "send-enrollment"
             ELSE IF s.imported = "none" THEN "obtain-storage"
             ELSE IF s.imported = "wrong" THEN "replace-storage"
             ELSE IF s.profile = "none" THEN "create-profile"
             ELSE "done"

SignEnrollment == /\ ~s.enrolled
                  /\ s' = [s EXCEPT !.enrolled = TRUE]
ExplainSend == /\ s.enrolled /\ ~s.explainedSend
               /\ s' = [s EXCEPT !.explainedSend = TRUE]
ReportSend == /\ s.explainedSend /\ ~s.sent
              \* A sender report does not change any recipient's files.
              /\ s' = [s EXCEPT !.sent = TRUE]
ReceiveEnrollment == /\ s.sent /\ ~s.enrollmentReceived
                     /\ s' = [s EXCEPT !.enrollmentReceived = TRUE]
AskStorage == /\ s.sent /\ ~s.askedStorage
              \* CLI identifies coordinator, exact public file and import action.
              /\ s' = [s EXCEPT !.askedStorage = TRUE]
CoordinatorProduce == /\ s.askedStorage /\ ~s.available
                      /\ s' = [s EXCEPT !.available = TRUE]
Deliver(v) == /\ s.available /\ v \in {"good", "wrong"}
              /\ s.delivered # v
              /\ s' = [s EXCEPT !.delivered = v]
Import == /\ s.askedStorage /\ s.delivered # "none"
          /\ s.imported # s.delivered
          /\ s' = [s EXCEPT !.imported = s.delivered, !.verified = "none"]
CreateProfile == /\ Recommend = "create-profile"
                 /\ s.imported = "good" /\ s.profile = "none"
                 \* Validation happens inside creation; wrong bytes cannot pass.
                 /\ s' = [s EXCEPT !.verified = s.imported,
                                    !.profile = s.imported]
Restart == /\ s.verified # "none"
           \* Durable files/reported exchanges survive. Cached verification does not.
           /\ s' = [s EXCEPT !.verified = "none"]
Next == SignEnrollment \/ ExplainSend \/ ReportSend \/ ReceiveEnrollment \/ AskStorage
        \/ CoordinatorProduce \/ (\E v \in {"good", "wrong"}: Deliver(v))
        \/ Import \/ CreateProfile \/ Restart
Spec == Init /\ [][Next]_vars

StorageBeforeRecommendation == Recommend = "create-profile" => s.imported # "none"
HandoffBeforeRecommendation == Recommend = "create-profile" => s.sent
VerifiedExactBytes == s.verified # "none" => s.verified = s.imported
ProfileBoundToValidBytes == s.profile \in {"none", "good"}

\* Deliberately false invariants used as reachability queries in separate runs.
NeverFinished == s.profile = "none"
NoUnacknowledgedSend == ~(s.sent /\ ~s.enrollmentReceived)
=======================================================================
