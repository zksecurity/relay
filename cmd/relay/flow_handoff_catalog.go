package main

import "strings"

// Additive tasks preserve existing task IDs and command-field indexes so saved
// operations remain interpretable. Human reports never replace command checks.
func roleFlowStages(role string) []flowStage {
	stages := baseRoleFlowStages(role)
	for si := range stages {
		stage := &stages[si]
		var tasks []flowTask
		if role == "auditor" && stage.ID == "audit" {
			tasks = append(tasks, handoff("receive-audit-inputs", "Receive the exact public audit package from the coordinator", "Ask the coordinator for the candidate directory, complete two-phase public transcript and Phase 1 seal. Put the candidate under /work/candidate and transcript under /work/ceremony/public (or select their actual paths in the audit). Independently check sources; receiving files is not verification."))
		}
		if role == "release-signer" && stage.ID == "assignment" {
			tasks = append(tasks, handoff("receive-signing-inputs", "Receive the complete public signing package", "Use the agreed public-file transfer procedure to receive the candidate directory, every selected auditor's report/signature pair, the signed operational bundle and its complete referenced evidence tree from the coordinator. Keep your signing host offline; do not reconnect it to download these files. Stage candidate in /work/candidate and evidence in /work/ceremony/public; retain relative paths. Obtain the coordinator key independently. No storage credentials belong on this machine. Receive missing files before retrying; do not waive verification."))
		}
		if role == "upload-station" && stage.ID == "upload" {
			tasks = append(tasks, handoff("receive-release", "Receive the signed public release from the final signer", "Ask the final signer for the complete signed public release directory and place it in /work/release. Obtain the signer public key independently in /trust/release-public-key.hex. Never receive the signer's private key. The next command verifies the release."))
		}
		if role == "coordinator" && stage.ID == "operational-evidence" {
			tasks = append(tasks, handoff("collect-submissions", "Collect the outstanding public records before preparing the bundle", "Ask each role for its upload manifest location or public evidence folder. Use View this area's actions: List submitted evidence, then Download submitted evidence. Retain original relative paths when placing records under /work/ceremony/public. Local downloads and reports are not signature verification; Prepare bundle identifies missing or invalid records. These collection actions remain available in this area and release."))
		}
		for _, task := range stage.Tasks {
			if role == "coordinator" && task.ID == "storage" {
				task.Label = "Share public storage settings with the online roles"
				task.Help = "In coordinator preparation, choose 10) Configure storage to generate /work/ceremony/config/relay-storage.json. Send ONLY that public file to participants, witnesses, mirrors, auditors and the upload station. They import it using setup 3 -> 4 before creating profiles. Do not send credential files, private grants or the final signer's private key. Successful preflight is required; reporting delivery does not verify receipt."
			}
			if stage.ID == "decision" && task.ID == "sign-decision" && role != "coordinator" {
				tasks = append(tasks, handoff("receive-decision", "Receive the canonical decision and its public evidence", "Ask the coordinator for the exact canonical decision.json and complete decision-evidence directory. Stage them under /work/decision.json and /work/decision-evidence, preserving relative paths. Review the exact bytes; the signing command verifies bindings before signing."))
			}
			if stage.ID == "decision" && task.ID == "verify-decision" {
				tasks = append(tasks, handoff("collect-decision-signatures", "Collect each accountable role's decision signature", "Request the signature file for this exact canonical decision from each required signer. Keep each under a distinct public filename; provide every required signature to the next verification command. Reported collection is not threshold verification."))
			}
			tasks = append(tasks, task)
			if role == "coordinator" && task.ID == "grant" {
				tasks = append(tasks, handoff("deliver-grant", "Privately deliver the issued participant grant", "Send the exact private grant file only to its named participant. Never put this file in public storage or public evidence. This step shows its recipient, path and expiry without printing credentials."))
			}
			if task.ID == "submit" && role != "upload-station" {
				tasks = append(tasks, handoff("notify-submission", "Tell the coordinator where your uploaded evidence is", "Standalone ceremony: send the manifest location printed by Upload signed PUBLIC output to your coordinator through the agreed channel. Tessera connection: upload reports the manifest automatically; check that notification succeeded before reporting this step. If notification failed, reopen the upload action to recover the same upload. Do not send grants or credentials. Delivery is not acceptance."))
			}
			if stage.ID == "decision" && task.ID == "prepare-decision" {
				tasks = append(tasks, handoff("deliver-decision", "Send the exact decision and evidence to the accountable signers", "Send decision.json and its complete referenced public decision-evidence tree to every required auditor and final signer. Preserve bytes and relative paths. Ask each owner to review, sign and return only their decision signature. Never request their signing key."))
			}
			if stage.ID == "decision" && task.ID == "sign-decision" && role != "coordinator" {
				tasks = append(tasks, handoff("return-decision-signature", "Return your public decision signature to the coordinator", "Send only the decision signature produced by your signing command. Identify the exact canonical decision it signs. Keep your private key; coordinator verification remains required."))
			}
		}
		if role == "coordinator" && stage.ID != "enrollments" && stage.ID != "decision" && stage.ID != "archive" && !strings.HasSuffix(stage.ID, "-turns") {
			has := map[string]bool{}
			for _, task := range tasks {
				has[task.ID] = true
			}
			if !has["evidence-grant"] {
				tasks = append(tasks, optional(evidenceGrantFlow()))
			}
			tasks = append(tasks, handoff("deliver-evidence-grant", "Privately deliver the evidence grant you issued", "Applies when you issued a standalone evidence grant here; no new grant is required for a role using its approved Tessera connection. Send the exact private file only to its named owner, never to public storage."))
			if !has["evidence-inbox"] {
				tasks = append(tasks, optional(flowTask{ID: "evidence-inbox", Label: "List submitted evidence for review", Help: "Find submissions reported by roles. A listing is not verification or acceptance.", Command: []string{"relay", "coordinator", "evidence"}, Fields: []flowField{storageField()}}))
			}
			if !has["evidence-receive"] {
				tasks = append(tasks, optional(flowTask{ID: "evidence-receive", Label: "Download submitted evidence for verification", Help: "Select the exact manifest reported by a role; download and hash-check into a fresh folder. Preserve relative paths when assembling public evidence. Signature checks remain required.", Command: []string{"relay", "coordinator", "evidence"}, Fields: []flowField{storageField(), ft("manifest-key", "Exact submitted manifest key", ""), ff("out-dir", "Fresh public evidence review folder", "/work/received-evidence")}}))
			}
		}
		// Download/access preparation must be reachable before a collection
		// checkpoint, not stranded behind that checkpoint's prerequisites.
		if role == "coordinator" {
			var accessTasks, rest []flowTask
			for _, task := range tasks {
				switch task.ID {
				case "evidence-grant", "deliver-evidence-grant", "evidence-inbox", "evidence-receive":
					accessTasks = append(accessTasks, task)
				default:
					rest = append(rest, task)
				}
			}
			tasks = append(accessTasks, rest...)
		}
		stage.Tasks = tasks
	}
	return stages
}
