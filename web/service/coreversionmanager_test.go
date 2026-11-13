package service

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func testSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestParseCoreVersionDigest(t *testing.T) {
	want := testSHA256([]byte("release"))
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
	sidecar := []byte(testSHA256(data) + "\n")
	if err := verifySidecar(data, sidecar); err != nil {
		t.Fatalf("valid checksum rejected: %v", err)
	}
	if err := verifySidecar(data, []byte(testSHA256([]byte("other")))); err == nil {
		t.Fatal("mismatched checksum accepted")
	}
	if err := verifySidecar(data, []byte("not-a-checksum")); err == nil {
		t.Fatal("invalid sidecar accepted")
	}
	if err := verifySidecar(data, []byte(testSHA256(data)+" extra")); err == nil {
		t.Fatal("ambiguous sidecar accepted")
	}
}

func makeAWGTestArchive(t *testing.T, mutate func(*zip.Writer) error) []byte {
	t.Helper()
	awg := []byte("not-an-elf-test-payload")
	quick := []byte("#!/bin/bash\necho test\n")
	files := map[string][]byte{
		"awg": awg,
		"awg-quick": quick,
		"awg.sha256": []byte(testSHA256(awg) + "\n"),
		"awg-quick.sha256": []byte(testSHA256(quick) + "\n"),
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
		"awg": []byte("payload"),
		"awg-quick": []byte("#!/bin/bash\n"),
		"awg.sha256": []byte(fmt.Sprintf("%s\n", testSHA256([]byte("wrong")))),
		"awg-quick.sha256": []byte(testSHA256([]byte("#!/bin/bash\n")) + "\n"),
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
