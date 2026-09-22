package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestDockerAdmissionSerializesSameDaemon(t *testing.T) {
	root := t.TempDir()
	first, err := acquireDockerAdmissionAt(root, "daemon-a")
	if err != nil {
		t.Fatal(err)
	}
	defer first.release()
	if second, err := acquireDockerAdmissionAt(root, "daemon-a"); err == nil {
		second.release()
		t.Fatal("concurrent admission acquired same daemon lock")
	}
	other, err := acquireDockerAdmissionAt(root, "daemon-b")
	if err != nil {
		t.Fatal(err)
	}
	other.release()
	if err := first.release(); err != nil {
		t.Fatal(err)
	}
	retry, err := acquireDockerAdmissionAt(root, "daemon-a")
	if err != nil {
		t.Fatal(err)
	}
	retry.release()
}

func TestDockerAdmissionLockDiesWithProcess(t *testing.T) {
	if root := os.Getenv("RELAY_ADMISSION_TEST_CHILD_ROOT"); root != "" {
		lock, err := acquireDockerAdmissionAt(root, "crash-test-daemon")
		if err != nil {
			t.Fatal(err)
		}
		defer lock.release()
		fmt.Println("admission-held")
		time.Sleep(time.Minute)
		return
	}
	root := t.TempDir()
	child := exec.Command(os.Args[0], "-test.run=^TestDockerAdmissionLockDiesWithProcess$")
	child.Env = append(os.Environ(), "RELAY_ADMISSION_TEST_CHILD_ROOT="+root)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "admission-held\n" {
			t.Fatal("child did not acquire admission", line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child admission timed out")
	}
	if lock, err := acquireDockerAdmissionAt(root, "crash-test-daemon"); err == nil {
		lock.release()
		t.Fatal("second process bypassed admission")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	lock, err := acquireDockerAdmissionAt(root, "crash-test-daemon")
	if err != nil {
		t.Fatal("crashed process left an admission lock", err)
	}
	lock.release()
}
