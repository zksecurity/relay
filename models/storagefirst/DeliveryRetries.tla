------------------------ MODULE DeliveryRetries ------------------------
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS MaxAttempts, Results, ForceReplacement
VARIABLES deliveries, uploaded, rejected, accepted
vars == <<deliveries, uploaded, rejected, accepted>>

Active == {i \in 1..Len(deliveries) : deliveries[i] = "allocated"}
Init ==
  /\ deliveries = <<>>
  /\ uploaded = [i \in 1..MaxAttempts |-> "none"]
  /\ rejected = {}
  /\ accepted = "none"

Allocate ==
  /\ Active = {}
  /\ accepted = "none"
  /\ Len(deliveries) < MaxAttempts
  /\ deliveries' = Append(deliveries, "allocated")
  /\ UNCHANGED <<uploaded, rejected, accepted>>

Deliver(i, result) ==
  /\ i \in Active
  /\ uploaded[i] = "none"
  /\ result \in Results
  /\ uploaded' = [uploaded EXCEPT ![i] = result]
  /\ UNCHANGED <<deliveries, rejected, accepted>>

Retire(i) ==
  /\ i \in Active
  \* The reviewed bug required replacement even at the history limit.
  /\ ~ForceReplacement \/ Len(deliveries) < MaxAttempts
  /\ deliveries' = [deliveries EXCEPT ![i] = "retired"]
  /\ UNCHANGED <<uploaded, rejected, accepted>>

Reject(i) ==
  /\ i \in Active
  /\ uploaded[i] \in Results
  /\ ~ForceReplacement \/ Len(deliveries) < MaxAttempts
  /\ deliveries' = [deliveries EXCEPT ![i] = "rejected"]
  /\ rejected' = rejected \cup {uploaded[i]}
  /\ UNCHANGED <<uploaded, accepted>>

Accept(i) ==
  /\ i \in Active
  /\ uploaded[i] \in Results \ rejected
  /\ deliveries' = [deliveries EXCEPT ![i] = "accepted"]
  /\ accepted' = uploaded[i]
  /\ UNCHANGED <<uploaded, rejected>>

Restart == UNCHANGED vars
Next == Allocate \/ Restart \/
  (\E i \in 1..MaxAttempts : Retire(i) \/ Reject(i) \/ Accept(i) \/
    (\E result \in Results : Deliver(i, result)))
Spec == Init /\ [][Next]_vars

BoundedHistory == Len(deliveries) <= MaxAttempts
OneActive == Cardinality(Active) <= 1
RejectedCannotBeAccepted == accepted \notin rejected
AcceptanceIsTerminal == accepted # "none" => Active = {}
ActiveCanRetire == Active # {} => (\E i \in Active : ENABLED Retire(i))
NeverAccepted == accepted = "none"
=======================================================================
