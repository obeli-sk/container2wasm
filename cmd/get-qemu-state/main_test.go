package main

import (
	"bytes"
	"testing"
)

func TestRequestMigrationKeepsSourceRunning(t *testing.T) {
	var monitor bytes.Buffer
	if err := requestMigration(&monitor, "/tmp/vm.state"); err != nil {
		t.Fatal(err)
	}
	if got, want := monitor.String(), "migrate file:/tmp/vm.state\n"; got != want {
		t.Fatalf("monitor command = %q, want %q", got, want)
	}
}
