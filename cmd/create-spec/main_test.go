package main

import (
	"slices"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestGenerateSpecActivityVMNetAdmin(t *testing.T) {
	spec, err := generateSpec(ocispec.Image{Platform: ocispec.Platform{Architecture: "amd64"}}, t.TempDir(), false, true)
	if err != nil {
		t.Fatal(err)
	}

	for name, capabilities := range map[string][]string{
		"bounding":  spec.Process.Capabilities.Bounding,
		"effective": spec.Process.Capabilities.Effective,
		"permitted": spec.Process.Capabilities.Permitted,
	} {
		if !slices.Contains(capabilities, "CAP_NET_ADMIN") {
			t.Errorf("%s capabilities do not contain CAP_NET_ADMIN: %v", name, capabilities)
		}
	}
}

func TestGenerateSpecDoesNotGrantNetAdminByDefault(t *testing.T) {
	spec, err := generateSpec(ocispec.Image{Platform: ocispec.Platform{Architecture: "amd64"}}, t.TempDir(), false, false)
	if err != nil {
		t.Fatal(err)
	}

	if slices.Contains(spec.Process.Capabilities.Effective, "CAP_NET_ADMIN") {
		t.Errorf("effective capabilities unexpectedly contain CAP_NET_ADMIN: %v", spec.Process.Capabilities.Effective)
	}
}
