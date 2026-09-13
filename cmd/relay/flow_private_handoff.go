package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

func grantDeliveryTask(task flowTask) bool {
	return task.ID == "deliver-grant" || task.ID == "deliver-evidence-grant"
}

func (f *roleFlow) grantForDelivery(task flowTask) *flowAttempt {
	id := "grant"
	if task.ID == "deliver-evidence-grant" {
		id = "evidence-grant"
	}
	a := f.last(flowTask{ID: id})
	if a == nil || a.Status != "succeeded" {
		return nil
	}
	return a
}

func (f *roleFlow) grantDeliveryComplete(task flowTask) bool {
	a := f.grantForDelivery(task)
	if a == nil {
		return task.ID == "deliver-evidence-grant"
	}
	path, err := f.publicHostPath(commandValue(a.Command, "out"))
	if err != nil {
		return false
	}
	if _, err := readProtectedCredentialBytes(path, 1<<20); err != nil {
		return false
	}
	digest, err := setupFileHash(path)
	return err == nil && f.state.Values["private-delivery/"+a.ID] == digest
}

func (f *roleFlow) deliverPrivateGrant(task flowTask) error {
	a := f.grantForDelivery(task)
	if a == nil {
		return errors.New("issue the matching grant first; roles with Tessera connections do not need a standalone evidence grant")
	}
	path, err := f.publicHostPath(commandValue(a.Command, "out"))
	if err != nil {
		return err
	}
	if _, err := readProtectedCredentialBytes(path, 1<<20); err != nil {
		return errors.New("issued grant must remain a protected local file")
	}
	g, err := loadGrant(path)
	if err != nil {
		return errors.New("issued grant cannot be validated; inspect the grant action without displaying credentials")
	}
	if g.IdentityID != commandValue(a.Command, "identity") {
		return errors.New("grant recipient differs from the recorded issuance")
	}
	if g.Role != commandValue(a.Command, "role") {
		return errors.New("grant role differs from the recorded issuance")
	}
	storagePath, err := f.publicHostPath(commandValue(a.Command, "storage"))
	if err != nil {
		return err
	}
	var storage access.StorageConfig
	if err := setupReadJSON(storagePath, &storage); err != nil {
		return errors.New("cannot load the issuance storage context")
	}
	if err := storage.Validate(); err != nil || storage.CeremonyID != g.CeremonyID {
		return errors.New("grant does not match the issuance ceremony")
	}
	if err := g.CheckUsable(time.Now()); err != nil {
		return errors.New("grant has insufficient time remaining; return to the issuance action for fresh access before delivering")
	}
	digest, err := setupFileHash(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(f.ui.output, "PRIVATE HANDOFF\nRecipient: %s (%s)\nFile: %s\nExpires: %s\nSend only to this recipient through your private coordination channel. Never publish this file.\n", g.IdentityID, g.Role, path, g.ExpiresAt)
	choice, err := f.ui.choose("Private grant delivery", "", []setupChoice{{"sent", "I sent this exact grant to its named owner"}, {"waiting", "Not yet — leave delivery waiting"}})
	if err != nil || choice == "waiting" {
		return err
	}
	after, err := setupFileHash(path)
	if err != nil || after != digest {
		return errors.New("grant changed during review; inspect the issuance before sending")
	}
	f.state.Values["private-delivery/"+a.ID] = digest
	fmt.Fprintln(f.ui.output, "Delivery reported, not recipient receipt. Only a local digest was recorded; no grant contents were copied to public evidence.")
	return f.save()
}
