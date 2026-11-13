// Package awgsrc embeds the vendored AmneziaWG Linux kernel-module source tree so the
// panel can DKMS-build the out-of-tree `amneziawg` module on the target host at provision
// time. This is the project's only on-host compile: unlike the bundled static daemons, a
// kernel module must match the running kernel, so it cannot be prebuilt. The source under
// src/ is a pinned copy of github.com/amnezia-vpn/amneziawg-linux-kernel-module.
// The Git blob IDs of all 112 vendored src/ files match the official upstream
// tree at SourceCommit exactly; unrelated upstream test/build files are not vendored.
package awgsrc

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed all:src
var srcFS embed.FS

// Version is the DKMS package version (matches src/dkms.conf PACKAGE_VERSION).
// It is intentionally distinct from KernelVersion: DKMS tracks its own package
// identity, while modinfo reports the upstream AmneziaWG implementation version.
const Version = "1.0.0"

// KernelVersion is the version from src/version.h in the pinned source tree.
const KernelVersion = "1.0.20260611"

// SourceRepo and SourceCommit identify the exact official upstream source snapshot.
// SourceCommit is the merge commit for the official 1.0.20260611 version bump;
// the vendored src/ files have been checked against its Git tree.
const SourceRepo = "amnezia-vpn/amneziawg-linux-kernel-module"
const SourceCommit = "2a6e1a02ac024f54a23e18f894a279b7f870b8fb"

// Extract writes the embedded module source tree into destDir (destDir gets Makefile,
// Kbuild, dkms.conf, the .c/.h files, and the compat/ + crypto/ subdirs directly). The
// caller then runs `make -C destDir dkms-install` + dkms add/build/install.
func Extract(destDir string) error {
	sub, err := fs.Sub(srcFS, "src")
	if err != nil {
		return err
	}
	return fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(destDir, path)
		if d.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		data, err := fs.ReadFile(sub, path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0644)
	})
}
