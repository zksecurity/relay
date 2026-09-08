package main

// Reviewed command recipes. Operators choose values, never shell fragments.
// Externally authored public evidence remains an explicit handoff, not a claim
// that this UI observed publication, established independence, or made a proof.
func ff(flag, label, value string) flowField {
	return flowField{Flag: flag, Label: label, Default: value, Kind: "path"}
}
func ft(flag, label, value string) flowField {
	return flowField{Flag: flag, Label: label, Default: value}
}
func nowField(flag string) flowField {
	return flowField{Flag: flag, Label: "Actual action time (UTC)", Default: "NOW", Kind: "time"}
}
func authFields() []flowField {
	return []flowField{ff("ceremony", "Signed ceremony definition", "/work/ceremony/public/ceremony.json"), ff("ceremony-signature", "Definition signature", "/work/ceremony/public/ceremony.sig"), ff("coordinator-public-key-file", "Independently authenticated coordinator public key", "/trust/coordinator-public-key.hex")}
}
func flowProof(id, label, help string, command ...string) flowTask {
	return flowTask{ID: id, Label: label, Help: help, Command: append([]string{"mpc-ceremony"}, command...), Fields: authFields()}
}
func handoff(id, label, help string) flowTask {
	return flowTask{ID: id, Label: label, Help: help, Handoff: true}
}
func withFields(task flowTask, fields ...flowField) flowTask {
	task.Fields = append(task.Fields, fields...)
	return task
}
func optional(task flowTask) flowTask { task.Optional = true; return task }
func inspectFlow() flowTask {
	return withFields(flowProof("inspect", "Authenticate and inspect retained state", "Authenticates discovered state for read-only review. This does not replay contribution mathematics or authorize signing.", "inspect"), ff("transcript-dir", "Transcript directory", "/work/ceremony/public"))
}
func phaseChain(phase string) []flowField {
	return []flowField{ff("transcript-dir", "Transcript directory", "/work/ceremony/public"), ff("chain", "Exact accepted chain (not an unverified latest head)", "/work/ceremony/public/"+phase+"/chain-0001.json"), ff("chain-signature", "Matching chain signature", "/work/ceremony/public/"+phase+"/chain-0001.sig")}
}
func sealFields() []flowField {
	return []flowField{ff("phase1-seal", "Phase 1 seal", "/work/ceremony/public/phase1/sealed/seal.json"), ff("phase1-seal-signature", "Phase 1 seal signature", "/work/ceremony/public/phase1/sealed/seal.sig")}
}
func replayFields() []flowField {
	fields := []flowField{ff("transcript-root", "Complete retained transcript root", "/work/ceremony/public")}
	for _, phase := range []string{"phase1", "phase2"} {
		for _, artifact := range []string{"chain", "close", "beacon"} {
			name := artifact
			if artifact == "close" {
				name = "closure/record"
			}
			if artifact == "beacon" {
				name = "beacon/record"
			}
			if artifact == "chain" {
				name = "chain-0001"
			}
			fields = append(fields, ff(phase+"-"+artifact, "Exact "+phase+" "+artifact, "/work/ceremony/public/"+phase+"/"+name+".json"), ff(phase+"-"+artifact+"-signature", "Matching signature", "/work/ceremony/public/"+phase+"/"+name+".sig"))
		}
	}
	return append(fields, sealFields()...)
}
func storageField() flowField {
	return ff("storage", "Verified storage configuration", "/work/ceremony/config/relay-storage.json")
}
func profileField(role, phase string) flowField {
	return ff("config", "Authenticated role profile", "/work/ceremony/config/"+role+"-"+phase+".json")
}
func publishFlow(phase string, closed bool) flowTask {
	command := []string{"relay", "coordinator", "publish", "--verify"}
	label := "Publish authenticated accepted head"
	if closed {
		command = append(command, "--closed")
		label = "Publish signed closure for witnesses"
	}
	task := flowTask{ID: "publish", Label: label, Help: "Rechecks every uploaded object. Share the publication location with witnesses immediately after closure.", Command: command, Fields: []flowField{storageField()}}
	fields := phaseChain(phase)[1:]
	if !closed {
		fields[0].Default = "/work/ceremony/public/" + phase + "/chain-0000.json"
		fields[1].Default = "/work/ceremony/public/" + phase + "/chain-0000.sig"
	}
	return withFields(task, fields...)
}
func enrollmentFlow() flowTask {
	return withFields(flowProof("enrollment", "Verify a signed enrollment", "Repeat for each enrollment received. The signature binds an identity to this ceremony, not an independent human.", "inspect", "enrollment"), ff("enrollment", "Signed public enrollment", "/work/enrollment.json"), ff("enrollment-signature", "Enrollment signature", "/work/enrollment.sig"))
}
func releaseVerifyFlow() flowTask {
	return withFields(flowProof("release-verify", "Independently verify the final release", "Verifies the bundled audits, transcript, keys, exports and signatures. Obtain the signer public key independently.", "release", "verify"), ff("keys-dir", "Complete signed release directory", "/work/release"), ff("manifest-public-key-file", "Trusted final-parameter signer public key", "/trust/release-public-key.hex"), ft("signature-key-id", "Final-parameter signer's key ID", ""))
}
func submitFlow(role, phase string) flowTask {
	command := []string{"relay", role, "submit"}
	return flowTask{ID: "submit", Label: "Upload signed PUBLIC output", Help: "Stage only the signed public output, never signing keys or grant contents. Send the resulting manifest key to the coordinator; submission is not acceptance.", Command: command, Fields: []flowField{profileField(role, phase), ff("grant", "Fresh private role grant file", "/work/"+role+".grant.json"), ff("dir", "Directory containing only signed public outputs", "/work/signed-output")}}
}

func importReceiptFlow(role, phase string) flowTask {
	kind := "public-witness"
	if role == "mirror" {
		kind = "mirror-receipt"
	}
	return withFields(flowProof("import-signature", "Verify and import your offline receipt signature", "The tool checks the raw signature over the exact canonical record before producing a detached signature. A coordinator-provided signature is not your observation.", "ops", "import-signature"), ft("record-type", "Receipt type", kind), ff("canonical", "Exact reviewed canonical receipt", "/work/"+phase+"-receipt/canonical.json"), ff("signer-public-key-file", "Your public signing key", "/trust/my-public-key.hex"), ff("raw-signature", "Returned raw offline signature", "/work/"+phase+"-receipt/raw-signature.hex"), ff("out", "Fresh verified detached signature", "/work/"+phase+"-receipt/receipt.sig"))
}

func mirrorDraftFlow(phase string) flowTask {
	return flowTask{ID: "draft-receipt", Label: "Draft a receipt for your retained head", Help: "Record the real storage location and time. Only a digest of the location goes in the public receipt.", Command: []string{"relay", "mirror", "receipt"}, Fields: []flowField{profileField("mirror", phase), ff("chain", "Exact retained chain", "/work/ceremony/public/"+phase+"/chain-0001.json"), ff("chain-signature", "Matching chain signature", "/work/ceremony/public/"+phase+"/chain-0001.sig"), {Flag: "index", Label: "Accepted contribution index retained", Kind: "number"}, ft("location", "Actual retained-copy location URI", ""), {Flag: "stored-at", Label: "Actual time this copy was stored (UTC)", Kind: "time"}, ff("out", "Fresh mirror receipt draft", "/work/receipt.json")}}
}

func evidenceGrantFlow() flowTask {
	return flowTask{ID: "evidence-grant", Label: "Issue an enrolled role's evidence upload grant", Help: "Repeat for each role. Authenticate the enrollment first and deliver each private grant only to its named owner.", Command: []string{"relay", "coordinator", "grant"}, Fields: []flowField{storageField(), {Flag: "role", Label: "Evidence role", Default: "witness", Choices: []string{"witness", "mirror", "auditor", "release", "decision"}}, ft("identity", "Enrolled public identity ID", ""), ff("enrollment", "Verified enrollment", "/work/enrollment.json"), ff("enrollment-signature", "Enrollment signature", "/work/enrollment.sig"), ft("credential-ttl", "Grant lifetime", "2h"), ft("minimum-remaining", "Minimum remaining time", "1h"), ff("out", "Fresh private grant file", "/work/evidence.grant.json")}}
}

func decisionFlow(role string) flowStage {
	stage := flowStage{ID: "decision", Label: "Production decision (not applicable to a tiny rehearsal)"}
	if role == "coordinator" {
		prepare := withFields(flowProof("prepare-decision", "Prepare the canonical GO/NO-GO decision", "Production only. Supply the reviewed decision draft and complete evidence bindings; the tool rejects tiny rehearsals as production evidence.", "decision", "prepare"), ff("draft", "Reviewed production decision draft", "/work/decision-draft.json"), ff("out", "Fresh canonical decision", "/work/decision.json"))
		stage.Tasks = append(stage.Tasks, optional(prepare))
	}
	signerRole := role
	if role == "release-signer" {
		signerRole = "release_signer"
	}
	sign := withFields(flowProof("sign-decision", "Verify evidence and sign your accountable decision", "Production only. All named accountable roles sign the same canonical decision. A GO requires full evidence verification before the signing key is used.", "decision", "sign"), ff("decision", "Exact canonical decision", "/work/decision.json"), ff("evidence-root", "Complete decision evidence root", "/work/decision-evidence"), ft("role", "Your accountable role", signerRole), ft("signer-id", "Your enrolled public identity ID", ""), ff("signing-key", "Your own signing key", "/keys/signing.hex"), ff("out", "Fresh decision signature", "/work/decision-"+role+".sig"))
	stage.Tasks = append(stage.Tasks, optional(sign))
	if role == "coordinator" {
		verify := withFields(flowProof("verify-decision", "Verify the complete decision signature threshold", "Production only. Include every signature required by the canonical decision. Verification must pass before release authorization.", "decision", "verify"), ff("decision", "Canonical production decision", "/work/decision.json"), ff("signature", "Coordinator decision signature", "/work/decision-coordinator.sig"), ff("signature", "First auditor decision signature", "/work/decision-auditor-01.sig"), ff("signature", "Second auditor decision signature", "/work/decision-auditor-02.sig"), ff("signature", "Final-parameter signer decision signature", "/work/decision-release-signer.sig"), ff("evidence-root", "Complete evidence root", "/work/decision-evidence"))
		verify.ExtraLabel = "Number of additional required decision signatures"
		verify.ExtraFields = []flowField{ff("signature", "Additional accountable role signature", "")}
		stage.Tasks = append(stage.Tasks, optional(verify))
	}
	stage.Tasks = append(stage.Tasks, handoff("decision-scope", "Record decision scope and authorization", "For production, retain the successfully verified decision and every required accountable signature. For a tiny rehearsal, record that this production gate is not applicable. The local checklist cannot waive a production release gate."))
	return stage
}

func coordinatorFlowStages() []flowStage {
	stages := []flowStage{{ID: "enrollments", Label: "Assignments and enrollments", Tasks: []flowTask{
		inspectFlow(), enrollmentFlow(), handoff("assignments", "Confirm assignment review and enrollment collection", "Distribute the exact signed definition through your agreed channel. Collect reviewed proof-of-possession enrollments from all required roles, including witnesses and mirrors. Other roles retain their private keys."),
	}}, {ID: "storage", Label: "Storage and first publication", Tasks: []flowTask{
		handoff("storage", "Confirm storage preflight completed", "Use coordinator preparation to configure administrator-provisioned storage. Require successful public-read/private-inbox/freshness/scope checks. This workflow does not provision billable cloud resources."), publishFlow("phase1", false),
	}}}
	for _, phase := range []string{"phase1", "phase2"} {
		grant := flowTask{ID: "grant", Label: "Issue the next participant's private grant", Help: "Check the signed schedule and do not overlap turns. Privately send the resulting grant only to its named participant.", Command: []string{"relay", "coordinator", "grant", "--role", "participant"}, Fields: []flowField{storageField(), ft("identity", "Next participant ID", ""), ft("credential-ttl", "Grant lifetime", "2h"), ft("minimum-remaining", "Minimum time remaining to start", "1h"), ff("out", "Fresh private grant output", "/work/"+phase+"-participant.grant.json")}}
		accept := flowTask{ID: "accept", Label: "Verify and accept one submitted candidate", Help: "Repeat this turn for each participant. Acceptance verifies the candidate and publishes the advanced head.", Command: []string{"relay", "coordinator", "accept", "--verify-publish"}, Fields: []flowField{storageField(), ft("candidate-key", "Candidate manifest key received from the participant", ""), ff("coordinator-signing-key", "Your coordinator signing key", "/keys/signing.hex")}}
		if phase == "phase2" {
			accept.Fields = append(accept.Fields, sealFields()...)
		}
		stages = append(stages, flowStage{ID: phase + "-turns", Label: phase + " participant turns", Tasks: []flowTask{inspectFlow(), grant, accept, handoff("turns-complete", "Confirm all intended turns are accepted", "Repeat grant and acceptance for each scheduled participant. Reauthenticate the head after each acceptance. Closing will independently enforce the signed minimum; do not treat an inbox listing as acceptance.")}})
		closeTask := withFields(flowProof("close", "Replay and close the phase", "Tell witnesses to start observing BEFORE closing. The tool selects a future beacon round after replay; do not fabricate or backdate witness claims.", phase, "close"), phaseChain(phase)...)
		closeTask.Fields = append(closeTask.Fields, ff("coordinator-signing-key", "Your coordinator signing key", "/keys/signing.hex"), flowField{Flag: "beacon-round-lead", Label: "Seconds allowed for public witnessing after closure", Default: "300", Kind: "number"})
		if phase == "phase2" {
			closeTask.Fields = append(closeTask.Fields, sealFields()...)
		}
		beacon := withFields(flowProof("beacon", "Authenticate and record the agreed beacon response", "Wait for the exact round committed in the closure. Retrieve and retain responses from the required independent relay operators. The proof tool verifies the supplied raw response cryptographically; the guide never chooses another round.", phase, "beacon"), ff("closure", "Signed phase closure", "/work/ceremony/public/"+phase+"/closure/record.json"), ff("closure-signature", "Closure signature", "/work/ceremony/public/"+phase+"/closure/record.sig"), ff("raw-response", "Archived raw response for the committed round", "/work/"+phase+"-beacon-response.json"), nowField("published-at"), ff("coordinator-signing-key", "Your coordinator signing key", "/keys/signing.hex"), ff("transcript-dir", "Transcript directory", "/work/ceremony/public"))
		stages = append(stages, flowStage{ID: phase + "-close", Label: phase + " closure and public beacon", Tasks: []flowTask{handoff("witnesses-ready", "Confirm witnesses are observing", "Ask each witness to confirm readiness through your coordination channel."), closeTask, publishFlow(phase, true), handoff("observations", "Collect the public-witness and beacon-relay evidence", "Witnesses must preserve exact public closure bytes and sign only what they observed before the beacon window ends. Wait for the committed round and collect distinct relay responses. Missing or conflicting evidence requires investigation."), beacon}})
		if phase == "phase1" {
			seal := withFields(flowProof("seal", "Seal Phase 1 with its verified beacon", "This independently replays Phase 1 and applies its authenticated beacon.", "phase1", "seal"), ff("transcript-dir", "Phase 1 transcript", "/work/ceremony/public"), ff("closure", "Phase 1 closure", "/work/ceremony/public/phase1/closure/record.json"), ff("closure-signature", "Closure signature", "/work/ceremony/public/phase1/closure/record.sig"), ff("beacon", "Phase 1 beacon record", "/work/ceremony/public/phase1/beacon/record.json"), ff("beacon-signature", "Beacon signature", "/work/ceremony/public/phase1/beacon/record.sig"), ff("coordinator-signing-key", "Your coordinator signing key", "/keys/signing.hex"), ff("out-dir", "Fresh sealed output directory", "/work/ceremony/public/phase1/sealed"))
			init := withFields(flowProof("phase2-init", "Initialize circuit-specific Phase 2", "Use the exact verified Phase 1 seal and compiled circuit.", "phase2", "init"), ff("phase1-transcript-dir", "Phase 1 transcript", "/work/ceremony/public"))
			init.Fields = append(init.Fields, sealFields()...)
			init.Fields = append(init.Fields, ff("coordinator-signing-key", "Your coordinator signing key", "/keys/signing.hex"), ff("out-dir", "Fresh Phase 2 output directory", "/work/ceremony/public/phase2"))
			stages = append(stages, flowStage{ID: "phase2-init", Label: "Prepare Phase 2", Tasks: []flowTask{seal, init, publishFlow("phase2", false)}})
		}
	}
	prepare := withFields(flowProof("prepare", "Replay both phases and prepare preliminary final keys", "Preliminary keys are not the final candidate and cannot be released.", "finalize", "prepare"), replayFields()...)
	prepare.Fields = append(prepare.Fields, ff("coordinator-signing-key", "Your coordinator signing key", "/keys/signing.hex"), nowField("prepared-at"), ff("out-dir", "Fresh preliminary output directory", "/work/preliminary"))
	complete := withFields(flowProof("complete", "Verify public proof evidence and create the candidate", "The proof tool replays both phases again and validates the external public proof. Do not supply private witness inputs.", "finalize", "complete"), replayFields()...)
	complete.Fields = append(complete.Fields, ff("coordinator-signing-key", "Your coordinator signing key", "/keys/signing.hex"), ff("public-evidence", "Canonical external public proof evidence", "/work/public-finalization-evidence.json"), nowField("finalized-at"), ff("out-dir", "Fresh candidate directory", "/work/candidate"))
	stages = append(stages, flowStage{ID: "finalization", Label: "Finalize and request independent audits", Tasks: []flowTask{prepare, handoff("public-proof", "Obtain public finalization evidence", "Give the preliminary keys to the circuit's public-evidence generation process. It returns the public proof artifact. This guide does not generate private application inputs."), complete, handoff("audits", "Send the exact candidate for independent audits", "Each enrolled auditor independently acquires and replays the complete transcript. Collect signed passing reports, signed operational evidence, and resolve incidents before requesting final signing.")}})
	ops := withFields(flowProof("ops-verify", "Verify the complete signed operational bundle", "The separately prepared bundle must include both phases, custody transfers, witness/mirror evidence, and distinct beacon relay operators. Authenticated claims do not prove physical independence or erasure.", "ops", "verify"), ft("record-type", "Operational record type", "evidence-bundle"), ff("record", "Signed evidence bundle", "/work/ceremony/public/operational/evidence-bundle.json"), ff("signature", "Bundle signature", "/work/ceremony/public/operational/evidence-bundle.sig"), ff("signer-public-key-file", "Trusted bundle signer key", "/trust/coordinator-public-key.hex"), ff("evidence-root", "Complete evidence root", "/work/ceremony/public"))
	stages = append(stages, flowStage{ID: "release", Label: "Independent signing and release verification", Tasks: []flowTask{ops, handoff("signer", "Hand the verified candidate and evidence to the final signer", "The signer uses their separate offline workflow and returns only signed public output. The coordinator never receives their private key."), releaseVerifyFlow(), handoff("archive", "Confirm authorization, archive verification and retention", "Complete any ceremony-specific production GO/NO-GO decision with all accountable roles. Verify the archive, preserve evidence on required mirrors, and retire temporary access only after authorization. A tiny rehearsal is not a production approval.")}})
	// Grant/evidence discovery is available during each closure window; listings
	// remain discovery, never an acceptance decision.
	for i := range stages {
		if stages[i].ID == "phase1-close" || stages[i].ID == "phase2-close" {
			stages[i].Tasks = append(stages[i].Tasks, optional(evidenceGrantFlow()), optional(flowTask{ID: "evidence-inbox", Label: "List submitted evidence for review", Help: "Download into fresh review directories and verify each record with proof-tool. Listing an inbox does not validate its contents.", Command: []string{"relay", "coordinator", "evidence"}, Fields: []flowField{storageField()}}))
		}
	}
	// Preserve the final archive handoff until after the production decision.
	last := &stages[len(stages)-1]
	archive := last.Tasks[len(last.Tasks)-1]
	last.Tasks = last.Tasks[:len(last.Tasks)-1]
	return append(stages, decisionFlow("coordinator"), flowStage{ID: "archive", Label: "Archive and retention", Tasks: []flowTask{archive}})
}

func roleFlowStages(role string) []flowStage {
	if role == "coordinator" {
		return coordinatorFlowStages()
	}
	if role == "participant" {
		stages := []flowStage{{ID: "assignment", Label: "Identity and assignment review", Tasks: []flowTask{handoff("assignment", "Review your identity, assignment and cleanup precautions", "Generate your own identity and send only identity.json to the coordinator. Receive authenticated phase profiles. Confirm your assigned positions and independently authenticate the coordinator key. Docker cleanup does not exclude host/VM remnants; Linux requires native Docker and disabled swap.")}}}
		for _, phase := range []string{"phase1", "phase2"} {
			config := flowField{Flag: "config", Label: "Your host-local " + phase + " Docker profile", Kind: "host"}
			status := flowTask{ID: "status", Label: "Authenticate your assignment and current turn", Help: "Status does not contribute or clean an orphan. Confirm this is the expected phase and ceremony.", Command: []string{"status"}, Fields: []flowField{config}}
			run := flowTask{ID: "contribute", Label: "Contribute, confirm cleanup and upload", Help: "Wait for your coordinator's turn notice and fresh private grant. The host supervisor runs the isolated contributor, verifies removal, then separately asks about retained copies before signing/uploading.", Command: []string{"run"}, Fields: []flowField{config, {Flag: "grant", Label: "Private grant file on your machine", Kind: "host"}, {Flag: "resume-candidate", Label: "Existing public candidate after an interrupted turn", Kind: "host", Optional: true}}}
			stages = append(stages, flowStage{ID: phase, Label: phase + " contribution", Tasks: []flowTask{status, run, handoff("accepted", "Confirm independently verified coordinator acceptance", "Send the manifest key to the coordinator. A successful upload is not acceptance. After an interruption preserve the candidate, get a replacement grant if needed, and resume rather than recompute.")}})
		}
		return append(stages, flowStage{ID: "retention", Label: "Finish", Tasks: []flowTask{handoff("retain", "Retain public evidence and protect your identity key", "Follow the agreed retention plan. Report possible retained randomness or key exposure through the independent channel.")}})
	}
	stages := []flowStage{{ID: "assignment", Label: "Identity, assignment and enrollment", Tasks: []flowTask{handoff("assignment", "Confirm your identity and independently authenticated assignment", "Generate your own identity using the key-generation workflow; send only identity.json. Verify the coordinator key independently. Review the signed role assignment, retention requirements and public display name."), enrollmentFlow()}}}
	switch role {
	case "witness", "mirror":
		for _, phase := range []string{"phase1", "phase2"} {
			sync := flowTask{ID: "observe", Label: "Synchronize the authenticated public transcript", Help: "Use your independently operated source and record real observations. A witness --once check fails until a closure is available; run observation before the window closes.", Command: []string{"relay", role, "run"}, Fields: []flowField{profileField(role, phase)}}
			if role == "witness" {
				sync.Command = append(sync.Command, "--once")
			}
			var prepare flowTask
			if role == "witness" {
				prepare = withFields(flowProof("receipt", "Prepare your actual public observation receipt", "Preserve the exact public closure bytes. Enter when YOU observed them; no automatic timestamp is supplied. The tool validates timing/coherence, not whether you actually observed publication.", "ops", "prepare-public-witness-receipt"), ff("transcript-root", "Retained transcript", "/work/ceremony/public"), ff("closure", "Observed phase closure", "/work/ceremony/public/"+phase+"/closure/record.json"), ff("closure-signature", "Closure signature", "/work/ceremony/public/"+phase+"/closure/record.sig"), ff("witness-enrollment", "Your signed enrollment", "/work/enrollment.json"), ff("witness-enrollment-signature", "Enrollment signature", "/work/enrollment.sig"), ft("publication-location", "Actual publication URL you observed", ""), flowField{Flag: "observed-at", Label: "Actual observation time in UTC", Kind: "time"}, ff("out-dir", "Fresh unsigned receipt export", "/work/"+phase+"-receipt"))
			} else {
				prepare = withFields(flowProof("receipt", "Verify retained files and prepare mirror receipt", "First prepare the Relay mirror draft for the actual retained head. This command re-hashes all files and binds the receipt to your enrollment.", "ops", "prepare-mirror-receipt"), ff("draft", "Relay mirror receipt draft", "/work/receipt.json"), ff("transcript-root", "Retained transcript", "/work/ceremony/public"), ff("chain", "Exact retained chain", "/work/ceremony/public/"+phase+"/chain-0001.json"), ff("chain-signature", "Chain signature", "/work/ceremony/public/"+phase+"/chain-0001.sig"), ff("mirror-enrollment", "Your signed enrollment", "/work/enrollment.json"), ff("mirror-enrollment-signature", "Enrollment signature", "/work/enrollment.sig"), ff("out-dir", "Fresh unsigned receipt export", "/work/"+phase+"-receipt"))
			}
			tasks := []flowTask{sync}
			if role == "mirror" {
				tasks = append(tasks, mirrorDraftFlow(phase))
			}
			tasks = append(tasks, prepare, handoff("sign", "Review and sign the exact canonical receipt offline", "Use the approved offline signing process, then import and verify its raw signature with proof-tool. Transfer only signed public output to this online station. Never sign an observation you did not make."), importReceiptFlow(role, phase), submitFlow(role, phase))
			stages = append(stages, flowStage{ID: phase, Label: phase + " observation and signed receipt", Tasks: tasks})
		}
	case "auditor":
		audit := withFields(flowProof("audit", "Independently replay both phases and sign your audit", "Acquire the full transcript from independently checked mirrors first. The tool compiles the circuit, replays both phases and verifies the candidate before emitting a passing signed report.", "audit"), replayFields()...)
		audit.Fields = append(audit.Fields, ff("candidate-bundle", "Exact candidate to audit", "/work/candidate"), ft("auditor-id", "Your enrolled auditor ID", ""), ff("auditor-signing-key", "Your own auditor signing key", "/keys/signing.hex"), nowField("audited-at"), ff("out", "Fresh audit report output", "/work/audit.json"), ff("audit-signature", "Fresh audit signature output", "/work/audit.sig"))
		stages = append(stages, flowStage{ID: "audit", Label: "Acquire, replay and submit", Tasks: []flowTask{flowTask{ID: "sync", Label: "Synchronize from your reviewed mirror", Help: "Retain source evidence. Synchronization alone is not a full audit.", Command: []string{"relay", "auditor", "run"}, Fields: []flowField{profileField("auditor", "phase2")}}, audit, submitFlow("auditor", "phase2")}})
	case "release-signer":
		stages[0].Tasks = append(stages[0].Tasks, handoff("offline", "Confirm the signing machine is disconnected", "Preload the approved image. Disconnect the machine before review/signing; --network=none alone does not disconnect the host. Do not bring storage credentials onto it."))
		sign := withFields(flowProof("sign", "Verify audits/evidence and sign the final parameters", "Requires at least two distinct enrolled auditors and the signed operational bundle for both phases. This never mutates the candidate.", "release", "sign"), ff("candidate-bundle", "Exact audited candidate", "/work/candidate"))
		for n := 0; n < 2; n++ {
			sign.Fields = append(sign.Fields, ff("audit-report", "Signed audit report", ""), ff("audit-signature", "Matching audit signature", ""))
		}
		sign.Fields = append(sign.Fields, ff("operational-evidence-root", "Complete operational evidence root", "/work/ceremony/public"), ff("operational-bundle", "Signed operational bundle", "/work/ceremony/public/operational/evidence-bundle.json"), ff("operational-bundle-signature", "Operational bundle signature", "/work/ceremony/public/operational/evidence-bundle.sig"), ff("release-signing-key", "Your own final-parameter signing key", "/keys/signing.hex"), ft("signature-key-id", "Your enrolled signing key ID", ""), nowField("released-at"), ff("release-dir", "Fresh signed release output", "/work/release"))
		sign.ExtraLabel = "Number of audit pairs beyond the first two"
		sign.ExtraFields = []flowField{ff("audit-report", "Additional signed audit report", ""), ff("audit-signature", "Its matching audit signature", "")}
		stages = append(stages, flowStage{ID: "sign", Label: "Review, sign and hand off", Tasks: []flowTask{sign, releaseVerifyFlow(), handoff("handoff", "Transfer only the signed public release", "Use a separate upload station. Keep your private key offline; retain the verification and transfer records. Complete any required production decision before release authorization.")}})
	case "upload-station":
		stages = append(stages, flowStage{ID: "upload", Label: "Public release handoff", Tasks: []flowTask{releaseVerifyFlow(), submitFlow("release", "phase2"), handoff("accepted", "Confirm independently verified acceptance", "Send the manifest key to the coordinator. This station must not hold signing keys.")}})
	default:
		return nil
	}
	if role == "auditor" || role == "release-signer" {
		stages = append(stages, decisionFlow(role))
	}
	return append(stages, flowStage{ID: "retain", Label: "Retention and incident reporting", Tasks: []flowTask{handoff("retain", "Record the public archive and retention handoff", "Preserve the exact public evidence for the agreed period. Report verification failures or storage loss; never edit signed evidence to make a check pass.")}})
}
