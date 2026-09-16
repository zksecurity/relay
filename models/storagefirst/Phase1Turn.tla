-------------------------- MODULE Phase1Turn --------------------------
EXTENDS Integers, Sequences, TLC

CONSTANT Participant

VARIABLES root, objects, coordinatorJournal, participantLocal

vars == <<root, objects, coordinatorJournal, participantLocal>>

Stages == {
  "initial", "outbound-open", "receipt-accepted", "candidate-accepted"
}

Attempts == {"none", "receipt-1", "candidate-1"}

Checkpoint(sequence, parent, stage, receiptAttempt, candidateAttempt) ==
  [sequence |-> sequence,
   parent |-> parent,
   stage |-> stage,
   participant |-> Participant,
   receiptAttempt |-> receiptAttempt,
   candidateAttempt |-> candidateAttempt]

InitialCheckpoint == Checkpoint(0, "none", "initial", "none", "none")

Init ==
  /\ root = InitialCheckpoint
  /\ objects = {InitialCheckpoint}
  /\ coordinatorJournal = "idle"
  /\ participantLocal = [receiptUploaded |-> FALSE,
                          candidateComputed |-> FALSE,
                          candidateUploaded |-> FALSE]

OpenOutbound ==
  LET next == Checkpoint(1, root, "outbound-open", "receipt-1", "none") IN
    /\ root.stage = "initial"
    /\ coordinatorJournal = "idle"
    /\ coordinatorJournal' = "outbound-prepared"
    /\ objects' = objects \cup {next}
    /\ root' = next
    /\ UNCHANGED participantLocal

UploadReceipt ==
  /\ root.stage = "outbound-open"
  /\ ~participantLocal.receiptUploaded
  /\ participantLocal' = [participantLocal EXCEPT !.receiptUploaded = TRUE]
  /\ UNCHANGED <<root, objects, coordinatorJournal>>

AcceptReceipt ==
  LET next == Checkpoint(2, root, "receipt-accepted", "receipt-1", "candidate-1") IN
    /\ root.stage = "outbound-open"
    /\ participantLocal.receiptUploaded
    /\ objects' = objects \cup {next}
    /\ root' = next
    /\ coordinatorJournal' = "receipt-accepted"
    /\ UNCHANGED participantLocal

ComputeCandidate ==
  /\ root.stage = "receipt-accepted"
  /\ ~participantLocal.candidateComputed
  /\ participantLocal' = [participantLocal EXCEPT !.candidateComputed = TRUE]
  /\ UNCHANGED <<root, objects, coordinatorJournal>>

UploadCandidate ==
  /\ root.stage = "receipt-accepted"
  /\ participantLocal.candidateComputed
  /\ ~participantLocal.candidateUploaded
  /\ participantLocal' = [participantLocal EXCEPT !.candidateUploaded = TRUE]
  /\ UNCHANGED <<root, objects, coordinatorJournal>>

AcceptCandidate ==
  LET next == Checkpoint(3, root, "candidate-accepted", "receipt-1", "candidate-1") IN
    /\ root.stage = "receipt-accepted"
    /\ participantLocal.candidateUploaded
    /\ objects' = objects \cup {next}
    /\ root' = next
    /\ coordinatorJournal' = "candidate-accepted"
    /\ UNCHANGED participantLocal

Restart == UNCHANGED vars

Next == OpenOutbound \/ UploadReceipt \/ AcceptReceipt \/
        ComputeCandidate \/ UploadCandidate \/ AcceptCandidate \/ Restart

Spec == Init /\ [][Next]_vars

RootNamesPublishedObject == root \in objects
RootSequenceMatchesStage ==
  CASE root.stage = "initial" -> root.sequence = 0
    [] root.stage = "outbound-open" -> root.sequence = 1
    [] root.stage = "receipt-accepted" -> root.sequence = 2
    [] root.stage = "candidate-accepted" -> root.sequence = 3
    [] OTHER -> FALSE
CandidateRequiresAcceptedReceipt ==
  participantLocal.candidateComputed => root.stage \in {"receipt-accepted", "candidate-accepted"}
AcceptanceRequiresUpload ==
  root.stage = "candidate-accepted" => participantLocal.candidateUploaded
AttemptIsPreallocated ==
  /\ (participantLocal.receiptUploaded => root.receiptAttempt = "receipt-1")
  /\ (participantLocal.candidateComputed => root.candidateAttempt = "candidate-1")
=======================================================================
