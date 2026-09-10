package main

import "fmt"

// Templates aid writing; they never prove independence or waive signed review.
// They apply equally to rehearsal and production, without inferring either mode.
func (p *rolePreparer) disclosurePreset() (string, error) {
	fmt.Fprintln(p.ui.output, "Public disclosure — choose an editable starting point. These choices apply to rehearsals and production; select only what is accurate. Shared ownership does not establish independent operators.")
	choice, err := p.ui.choose("Disclosure starting point", "", []setupChoice{
		{"shared", "One operator, multiple roles"},
		{"organization", "Separate operators, shared organization or equipment"},
		{"separate", "No known shared operation"},
		{"custom", "Write my own"},
	})
	if err != nil {
		return "", err
	}
	ask := func(label string) (string, error) { return p.ui.required(label, "") }
	var text string
	switch choice {
	case "shared":
		roles, e := ask("Roles you operate (list the actual roles)")
		if e != nil {
			return "", e
		}
		shared, e := ask("Shared machines and organization (describe both; write none where appropriate)")
		if e != nil {
			return "", e
		}
		text = fmt.Sprintf("I operate %s. These roles share: %s.", roles, shared)
	case "organization":
		org, e := ask("Your organization or affiliation (or none)")
		if e != nil {
			return "", e
		}
		equipment, e := ask("Shared equipment or infrastructure (or none)")
		if e != nil {
			return "", e
		}
		roles, e := ask("Other roles with which you share the organization or equipment")
		if e != nil {
			return "", e
		}
		text = fmt.Sprintf("I operate the %s role for %s. Shared equipment or infrastructure: %s. The roles sharing the organization or equipment are: %s.", p.d.Role, org, equipment, roles)
	case "separate":
		org, e := ask("Your organizational affiliation (or none)")
		if e != nil {
			return "", e
		}
		text = fmt.Sprintf("I operate the %s role. To my knowledge, I do not share its signing key or signing machine with other role operators. My organizational affiliation is %s.", p.d.Role, org)
	case "custom":
		return ask("Public disclosure: describe who operates this role and any shared people, organizations or machines (do not include secrets)")
	}
	fmt.Fprintf(p.ui.output, "Draft disclosure (review for accuracy):\n%q\n", text)
	return p.ui.required("Edit the full disclosure, or press Enter to use the draft (do not include secrets)", text)
}
