package service

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func coreVersionTestSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestParseCoreVersionDigest(t *testing.T) {
	want := coreVersionTestSHA256([]byte("release"))
	got, err := parseCoreVersionDigest("sha256:" + want)
	if err != nil || got != want {
		t.Fatalf("parseCoreVersionDigest() = %q, %v; want %q", got, err, want)
	}
	for _, invalid := range []string{"", want, "sha1:" + want, "sha256:xyz", "sha256:" + want[:63]} {
		if _, err := parseCoreVersionDigest(invalid); err == nil {
			t.Errorf("parseCoreVersionDigest(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestValidateAWGToolsAssetURL(t *testing.T) {
	good := "https://github.com/amnezia-vpn/amneziawg-tools/releases/download/v3.1.20260812/" + coreVersionAWGToolsAsset
	if err := validateAWGToolsAssetURL(good, "v3.1.20260812", coreVersionAWGToolsAsset); err != nil {
		t.Fatalf("official asset URL rejected: %v", err)
	}
	bad := []string{
		"http://github.com/amnezia-vpn/amneziawg-tools/releases/download/v3.1.20260812/" + coreVersionAWGToolsAsset,
		"https://github.com.evil.example/amnezia-vpn/amneziawg-tools/releases/download/v3.1.20260812/" + coreVersionAWGToolsAsset,
		"https://github.com/amnezia-vpn/amneziawg-tools/releases/download/v3.1.20260811/" + coreVersionAWGToolsAsset,
		"https://github.com/amnezia-vpn/amneziawg-tools/releases/download/v3.1.20260812/other.zip",
		good + "?redirect=https://evil.example",
	}
	for _, raw := range bad {
		if err := validateAWGToolsAssetURL(raw, "v3.1.20260812", coreVersionAWGToolsAsset); err == nil {
			t.Errorf("unsafe asset URL accepted: %s", raw)
		}
	}
}

func TestVerifySidecar(t *testing.T) {
	data := []byte("known release file")
	sidecar := []byte(coreVersionTestSHA256(data) + "\n")
	if err := verifySidecar(data, sidecar); err != nil {
		t.Fatalf("valid checksum rejected: %v", err)
	}
	if err := verifySidecar(data, []byte(coreVersionTestSHA256([]byte("other")))); err == nil {
		t.Fatal("mismatched checksum accepted")
	}
	if err := verifySidecar(data, []byte("not-a-checksum")); err == nil {
		t.Fatal("invalid sidecar accepted")
	}
	if err := verifySidecar(data, []byte(coreVersionTestSHA256(data)+" extra")); err == nil {
		t.Fatal("ambiguous sidecar accepted")
	}
}

func makeAWGTestArchive(t *testing.T, mutate func(*zip.Writer) error) []byte {
	t.Helper()
	awg := []byte("not-an-elf-test-payload")
	quick := []byte("#!/bin/bash\necho test\n")
	files := map[string][]byte{
		"awg":              awg,
		"awg-quick":        quick,
		"awg.sha256":       []byte(coreVersionTestSHA256(awg) + "\n"),
		"awg-quick.sha256": []byte(coreVersionTestSHA256(quick) + "\n"),
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(coreVersionAWGToolsArchiveDir + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if mutate != nil {
		if err := mutate(zw); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractAWGToolsPayload(t *testing.T) {
	archive := makeAWGTestArchive(t, nil)
	payload, err := extractAWGToolsPayload(archive)
	if err != nil {
		t.Fatalf("valid test archive rejected: %v", err)
	}
	if string(payload.AWG) != "not-an-elf-test-payload" || !bytes.HasPrefix(payload.AWGQuick, []byte("#!")) {
		t.Fatal("archive payload did not match expected files")
	}
}

func TestExtractAWGToolsPayloadRejectsTamperedAndUnexpectedFiles(t *testing.T) {
	tampered := makeAWGTestArchive(t, func(zw *zip.Writer) error {
		w, err := zw.Create(coreVersionAWGToolsArchiveDir + "/extra")
		if err != nil {
			return err
		}
		_, err = w.Write([]byte("unexpected"))
		return err
	})
	if _, err := extractAWGToolsPayload(tampered); err == nil {
		t.Fatal("archive with an unexpected file was accepted")
	}

	traversal := makeAWGTestArchive(t, func(zw *zip.Writer) error {
		w, err := zw.Create("../escape")
		if err != nil {
			return err
		}
		_, err = w.Write([]byte("bad"))
		return err
	})
	if _, err := extractAWGToolsPayload(traversal); err == nil {
		t.Fatal("archive path traversal was accepted")
	}
}

func TestExtractAWGToolsPayloadRejectsChecksumMismatch(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := map[string][]byte{
		"awg":              []byte("payload"),
		"awg-quick":        []byte("#!/bin/bash\n"),
		"awg.sha256":       []byte(fmt.Sprintf("%s\n", coreVersionTestSHA256([]byte("wrong")))),
		"awg-quick.sha256": []byte(coreVersionTestSHA256([]byte("#!/bin/bash\n")) + "\n"),
	}
	for name, data := range files {
		w, err := zw.Create(coreVersionAWGToolsArchiveDir + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := extractAWGToolsPayload(buf.Bytes()); err == nil {
		t.Fatal("archive with mismatched file checksum was accepted")
	}
}

func TestAWGToolsBackupAndRestore(t *testing.T) {
	installDir := t.TempDir()
	backupDir := t.TempDir()
	manager := &CoreVersionManagerService{installDir: installDir, backupRoot: backupDir}

	awg := []byte("old awg executable")
	quick := []byte("#!/bin/bash\necho old\n")
	if err := os.WriteFile(filepath.Join(installDir, "awg"), awg, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installDir, "awg-quick"), quick, 0755); err != nil {
		t.Fatal(err)
	}

	backup, err := manager.createAWGToolsBackup("3.0.0", "3.1.0")
	if err != nil {
		t.Fatalf("create backup: %v", err)
	}
	if backup.ID == "" {
		t.Fatal("backup ID was empty")
	}
	if err := os.WriteFile(filepath.Join(installDir, "awg"), []byte("new awg"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(installDir, "awg-quick")); err != nil {
		t.Fatal(err)
	}

	if err := manager.restoreAWGToolsBackup(backup); err != nil {
		t.Fatalf("restore backup: %v", err)
	}
	gotAWG, err := os.ReadFile(filepath.Join(installDir, "awg"))
	if err != nil || !bytes.Equal(gotAWG, awg) {
		t.Fatalf("restored awg mismatch: %q, %v", gotAWG, err)
	}
	gotQuick, err := os.ReadFile(filepath.Join(installDir, "awg-quick"))
	if err != nil || !bytes.Equal(gotQuick, quick) {
		t.Fatalf("restored awg-quick mismatch: %q, %v", gotQuick, err)
	}
	st, err := os.Stat(filepath.Join(installDir, "awg"))
	if err != nil || st.Mode().Perm() != 0750 {
		t.Fatalf("restored awg mode = %v, %v; want 0750", st, err)
	}
}

func TestAWGToolsBackupRestoresOriginalAbsence(t *testing.T) {
	installDir := t.TempDir()
	backupDir := t.TempDir()
	manager := &CoreVersionManagerService{installDir: installDir, backupRoot: backupDir}

	backup, err := manager.createAWGToolsBackup("", "3.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installDir, "awg"), []byte("new file"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := manager.restoreAWGToolsBackup(backup); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(installDir, "awg")); !os.IsNotExist(err) {
		t.Fatalf("rollback should remove a file that did not exist before, stat error: %v", err)
	}
}

func TestAWGToolsBackupRejectsCorruptedSnapshot(t *testing.T) {
	installDir := t.TempDir()
	backupDir := t.TempDir()
	manager := &CoreVersionManagerService{installDir: installDir, backupRoot: backupDir}
	original := []byte("old awg")
	if err := os.WriteFile(filepath.Join(installDir, "awg"), original, 0755); err != nil {
		t.Fatal(err)
	}
	backup, err := manager.createAWGToolsBackup("3.0.0", "3.1.0")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(backupDir, backup.ID, "files", "awg")
	if err := os.WriteFile(snapshot, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.restoreAWGToolsBackup(backup); err == nil {
		t.Fatal("corrupted backup file was accepted")
	}
}

func TestAWGToolsRestoreRejectsIncompleteManifest(t *testing.T) {
	installDir := t.TempDir()
	backupDir := t.TempDir()
	manager := &CoreVersionManagerService{installDir: installDir, backupRoot: backupDir}
	if err := os.WriteFile(filepath.Join(installDir, "awg"), []byte("current"), 0755); err != nil {
		t.Fatal(err)
	}
	backup, err := manager.createAWGToolsBackup("3.0.0", "3.1.0")
	if err != nil {
		t.Fatal(err)
	}
	incomplete := *backup
	incomplete.Files = append([]coreVersionBackupFile(nil), backup.Files[:1]...)
	if err := manager.restoreAWGToolsBackup(&incomplete); err == nil {
		t.Fatal("incomplete backup manifest was accepted")
	}
	current, err := os.ReadFile(filepath.Join(installDir, "awg"))
	if err != nil || string(current) != "current" {
		t.Fatalf("restore changed files before rejecting the manifest: %q, %v", current, err)
	}
}

func TestAWGToolsRestoreRejectsDuplicateManifestEntries(t *testing.T) {
	installDir := t.TempDir()
	backupDir := t.TempDir()
	manager := &CoreVersionManagerService{installDir: installDir, backupRoot: backupDir}
	backup, err := manager.createAWGToolsBackup("", "3.1.0")
	if err != nil {
		t.Fatal(err)
	}
	duplicate := *backup
	duplicate.Files = []coreVersionBackupFile{backup.Files[0], backup.Files[0]}
	if err := manager.restoreAWGToolsBackup(&duplicate); err == nil {
		t.Fatal("duplicate backup manifest entry was accepted")
	}
}


func TestCoreVersionSourceRevisionHelpers(t *testing.T) {
	valid := strings.Repeat("a", 40)
	if !validGitCommitSHA(valid) {
		t.Fatal("valid 40-character commit SHA was rejected")
	}
	for _, invalid := range []string{"", "abc", strings.Repeat("g", 40), strings.Repeat("a", 41)} {
		if validGitCommitSHA(invalid) {
			t.Errorf("invalid commit SHA accepted: %q", invalid)
		}
	}
	wantURL := "https://github.com/" + coreVersionXrayRepo + "/commit/" + valid
	if got := sourceCommitURL(coreVersionXrayRepo, valid); got != wantURL {
		t.Fatalf("sourceCommitURL()=%q, want %q", got, wantURL)
	}
	if got := sourceCommitURL("attacker.example/repo", valid); got != "" {
		t.Fatalf("sourceCommitURL accepted an untrusted repository: %q", got)
	}
}

func TestParseAWGKernelVersionHeader(t *testing.T) {
	got, err := parseAWGKernelVersionHeader([]byte("#ifndef WIREGUARD_VERSION\n#define WIREGUARD_VERSION \"3.1.20260812\"\n#endif\n"))
	if err != nil {
		t.Fatalf("parseAWGKernelVersionHeader: %v", err)
	}
	if got != "3.1.20260812" {
		t.Fatalf("kernel version=%q, want 3.1.20260812", got)
	}
	for _, invalid := range [][]byte{
		[]byte("#define OTHER_VERSION \"3.1\""),
		[]byte("#define WIREGUARD_VERSION"),
		[]byte("#define WIREGUARD_VERSION \"\""),
	} {
		if _, err := parseAWGKernelVersionHeader(invalid); err == nil {
			t.Errorf("invalid version header was accepted: %q", invalid)
		}
	}
}
