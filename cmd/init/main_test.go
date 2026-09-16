package main

import "testing"

func TestParseInfoPackMountUsesDedicated9PDevice(t *testing.T) {
	info := parseInfo([]byte("p: obelisk-activity-vm-http\n"))
	if got, want := len(info.mounts), 1; got != want {
		t.Fatalf("mount count = %d, want %d", got, want)
	}
	mount := info.mounts[0]
	if got, want := mount.Source, "/mnt/wasi1/obelisk-activity-vm-http"; got != want {
		t.Errorf("source = %q, want %q", got, want)
	}
	if got, want := mount.Destination, "/obelisk-activity-vm-http"; got != want {
		t.Errorf("destination = %q, want %q", got, want)
	}
}

func TestParseInfoSquashFSStore(t *testing.T) {
	info := parseInfo([]byte("s: obelisk-activity-vm-store/store.squashfs\n"))
	if got, want := info.storeSquashFS, "obelisk-activity-vm-store/store.squashfs"; got != want {
		t.Fatalf("storeSquashFS = %q, want %q", got, want)
	}
}

func TestMountStoreSquashFSRejectsPathsOutside9PRoot(t *testing.T) {
	for _, path := range []string{"/store.squashfs", "../store.squashfs", "path/../../store.squashfs"} {
		if _, _, err := storeSquashFSMount("/unused", path); err == nil {
			t.Errorf("mountStoreSquashFS accepted %q", path)
		}
	}
}

func TestStoreSquashFSMountUsesWASI9PAndNixStore(t *testing.T) {
	source, destination, err := storeSquashFSMount(
		"/run/rootfs",
		"obelisk-activity-vm-store/store.squashfs",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := source, "/mnt/wasi0/obelisk-activity-vm-store/store.squashfs"; got != want {
		t.Errorf("source = %q, want %q", got, want)
	}
	if got, want := destination, "/run/rootfs/nix/store"; got != want {
		t.Errorf("destination = %q, want %q", got, want)
	}
}
