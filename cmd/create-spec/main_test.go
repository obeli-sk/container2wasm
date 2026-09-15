package main

import (
	"reflect"
	"testing"
)

func TestGenerateBootConfigInitializesActivityVMNftables(t *testing.T) {
	config, err := generateBootConfig(false, false, "/image", "/runtime", "/rootfs", true, "", false, true)
	if err != nil {
		t.Fatal(err)
	}

	want := [][]string{{"/usr/sbin/nft", "-f", "/etc/obelisk-activity-vm.nft"}}
	if !reflect.DeepEqual(config.CmdPreRun, want) {
		t.Fatalf("unexpected pre-snapshot commands: got %v, want %v", config.CmdPreRun, want)
	}
}

func TestGenerateBootConfigDoesNotInitializeNftablesByDefault(t *testing.T) {
	config, err := generateBootConfig(false, false, "/image", "/runtime", "/rootfs", true, "", false, false)
	if err != nil {
		t.Fatal(err)
	}

	if len(config.CmdPreRun) != 0 {
		t.Fatalf("unexpected pre-snapshot commands: %v", config.CmdPreRun)
	}
}
