package main

import "testing"

func TestParseDockerUsage(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
		ok    bool
	}{
		{`{"CPUPerc":"12.50%","MemUsage":"240.5MiB / 6GiB"}`, "actual CPU 12.50%; memory 240.5MiB / 6GiB", true},
		{`{"CPUPerc":"1.0%","MemUsage":"0B / 6GiB"}`, "actual CPU 1.0%; memory 0B / 6GiB", true},
		{`{"CPUPerc":"3%","MemUsage":"13.3kB / 6GiB"}`, "actual CPU 3%; memory 13.3kB / 6GiB", true},
		{`{"CPUPerc":"%%","MemUsage":"1MiB / 6GiB"}`, "", false},
		{`{"CPUPerc":"bad\nline","MemUsage":"1MiB / 6GiB"}`, "", false},
		{`{"CPUPerc":"12%","MemUsage":"unavailable"}`, "", false},
	} {
		got, ok := parseDockerUsage([]byte(tc.input))
		if got != tc.want || ok != tc.ok {
			t.Fatalf("parse %q = %q, %t; want %q, %t", tc.input, got, ok, tc.want, tc.ok)
		}
	}
}
