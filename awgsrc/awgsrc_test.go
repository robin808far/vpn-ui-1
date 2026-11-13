package awgsrc

import (
	"regexp"
	"strings"
	"testing"
)

func TestVendoredSourceMetadataMatchesEmbeddedFiles(t *testing.T) {
	dkms, err := srcFS.ReadFile("src/dkms.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dkms), `PACKAGE_VERSION="`+Version+`"`) {
		t.Fatalf("dkms.conf does not match DKMS Version %q", Version)
	}

	versionHeader, err := srcFS.ReadFile("src/version.h")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?m)^#define\s+WIREGUARD_VERSION\s+"([^"]+)"`).FindSubmatch(versionHeader)
	if len(match) != 2 || string(match[1]) != KernelVersion {
		t.Fatalf("version.h has %q, expected KernelVersion %q", match, KernelVersion)
	}
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(SourceCommit) {
		t.Fatalf("SourceCommit is not a full lowercase Git SHA: %q", SourceCommit)
	}
}
