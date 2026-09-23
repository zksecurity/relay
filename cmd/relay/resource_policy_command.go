package main

import (
	"bufio"
	"errors"
	"flag"
	"os"
)

// Resource policy is host-local and can be configured before onboarding creates
// a ceremony workspace. This never loads keys or changes a signed ceremony.
func runResourcePolicy(args []string) error {
	flags := flag.NewFlagSet("resources", flag.ContinueOnError)
	docker := flags.String("docker-cli", "docker", "local Docker CLI path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return errors.New("usage: relay resources [--docker-cli PATH]")
	}
	driver := dockerDriver{client: osDockerCommandClient{binary: *docker}}
	if err := driver.authenticateDaemon(); err != nil {
		return err
	}
	ui := coordinatorWizard{input: bufio.NewReader(os.Stdin), output: os.Stdout}
	return configureGuidedResourcePolicy(&ui, driver.client, driver.daemon)
}
