package service

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/awgsrc"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// Core Version Manager deliberately supports only components with a fixed,
// allowlisted upstream and publisher-provided SHA-256 metadata. Xray is embedded
// in the panel binary and the AmneziaWG kernel module is vendored/DKMS-built;
// neither can be safely replaced as a loose file by this manager.
const (
	coreVersionAWGToolsRepo       = "amnezia-vpn/amneziawg-tools"
	coreVersionAWGToolsAPI        = "https://api.github.com/repos/" + coreVersionAWGToolsRepo + "/releases/latest"
	coreVersionAWGToolsAsset      = "ubuntu-22.04-amneziawg-tools.zip"
	coreVersionAWGToolsArchiveDir = "ubuntu-22.04-amneziawg-tools"
	coreVersionBackupRoot         = "/var/lib/vpn-ui/core-version-backups"
	coreVersionMaxAPIBytes        = 1 << 20
	coreVersionMaxAssetBytes      = 8 << 20
	coreVersionMaxFileBytes       = 2 << 20
	coreVersionBackupRetention    = 10
)

var coreVersionUpdateMu sync.Mutex

var coreVersionIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,80}$`)
var coreVersionHexPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
var awgToolsVersionPattern = regexp.MustCompile(`(?i)amneziawg-tools\s+v?([0-9][A-Za-z0-9.+_-]*)`)
var glibcVersionPattern = regexp.MustCompile(`(?i)^glibc\s+(\d+)\.(\d+)`)

// CoreVersionManagerService resolves releases only from the fixed official
// registry above. installDir and backupRoot are overrideable in tests; a
// zero-value service uses the production paths.
type CoreVersionManagerService struct {
	installDir string
	backupRoot string
	client     *http.Client
}

type CoreVersionManagerInfo struct {
	CheckedAt  time.Time                 `json:"checkedAt"`
	Components []CoreVersionComponent    `json:"components"`
	Backups    []CoreVersionBackupInfo  `json:"backups"`
	Warning    string                    `json:"warning,omitempty"`
}

type CoreVersionComponent struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	CurrentVersion   string    `json:"currentVersion"`
	LatestVersion    string    `json:"latestVersion,omitempty"`
	SourceRepo       string    `json:"sourceRepo"`
	SourceURL        string    `json:"sourceUrl"`
	ReleaseURL       string    `json:"releaseUrl,omitempty"`
	PublishedAt      time.Time `json:"publishedAt,omitempty"`
	UpdateAvailable  bool      `json:"updateAvailable"`
	CanUpdate        bool      `json:"canUpdate"`
	Integrity        string    `json:"integrity,omitempty"`
	AssetSHA256      string    `json:"assetSha256,omitempty"`
	UpdateReason     string    `json:"updateReason,omitempty"`
}

type CoreVersionBackupInfo struct {
	ID            string    `json:"id"`
	Component     string    `json:"component"`
	FromVersion   string    `json:"fromVersion"`
	ToVersion     string    `json:"toVersion"`
	CreatedAt     time.Time `json:"createdAt"`
}

type CoreVersionUpdateResult struct {
	Component   string    `json:"component"`
	FromVersion string    `json:"fromVersion"`
	ToVersion   string    `json:"toVersion"`
	BackupID    string    `json:"backupId"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type coreVersionRelease struct {
	TagName     string                `json:"tag_name"`
	HTMLURL     string                `json:"html_url"`
	PublishedAt time.Time             `json:"published_at"`
	Assets      []coreVersionAsset    `json:"assets"`
}

type coreVersionAsset struct {
	Name               string `json:"name"`
	Size               int64  `json:"size"`
	Digest             string `json:"digest"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type coreVersionBackupManifest struct {
	ID          string                  `json:"id"`
	Component   string                  `json:"component"`
	FromVersion string                  `json:"fromVersion"`
	ToVersion   string                  `json:"toVersion"`
	CreatedAt   time.Time               `json:"createdAt"`
	Files       []coreVersionBackupFile `json:"files"`
}

type coreVersionBackupFile struct {
	Name    string `json:"name"`
	Existed bool   `json:"existed"`
	Mode    uint32 `json:"mode,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
}

type awgToolsPayload struct {
	AWG      []byte
	AWGQuick []byte
}

func (s *CoreVersionManagerService) installPath() string {
	if s.installDir != "" {
		return s.installDir
	}
	// Keep the distro/package-manager-owned binaries intact. /usr/local/bin is
	// intentionally preferred by the standard systemd PATH on supported hosts.
	return "/usr/local/bin"
}

func (s *CoreVersionManagerService) backupPath() string {
	if s.backupRoot != "" {
		return s.backupRoot
	}
	return coreVersionBackupRoot
}

func (s *CoreVersionManagerService) httpClient(allowedHosts ...string) *http.Client {
	if s.client != nil {
		return s.client
	}
	allowed := make(map[string]bool, len(allowedHosts))
	for _, host := range allowedHosts {
		allowed[strings.ToLower(host)] = true
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL.Scheme != "https" || req.URL.User != nil ||
				(req.URL.Port() != "" && req.URL.Port() != "443") ||
				!allowed[strings.ToLower(req.URL.Hostname())] {
				return fmt.Errorf("redirect to an untrusted host was rejected")
			}
			return nil
		},
	}
}

// GetInfo returns the installed versions, the latest trusted AWG Tools release,
// and the available rollback points. Components without a verifiable official
// release are shown as managed by the panel/build process, never as updatable.
func (s *CoreVersionManagerService) GetInfo() CoreVersionManagerInfo {
	now := time.Now().UTC()
	info := CoreVersionManagerInfo{CheckedAt: now}

	var core CoreService
	xray := core.xrayStatus()
	info.Components = append(info.Components, CoreVersionComponent{
		ID:              "xray",
		Name:            "Xray-core (patched, embedded)",
		CurrentVersion:  firstNonEmptyCoreVersion(xray.Version, currentXrayVersion(), "unknown"),
		SourceRepo:      "Sir-MmD/Xray-core",
		SourceURL:       "https://github.com/Sir-MmD/Xray-core",
		UpdateAvailable: false,
		CanUpdate:       false,
		UpdateReason:    "This fork has no published GitHub Release assets. Xray is pinned as a submodule and embedded in the panel binary; update it through a reviewed panel build, not by replacing the runtime file.",
	})
	info.Components = append(info.Components, CoreVersionComponent{
		ID:              "awg-kmod",
		Name:            "AmneziaWG kernel module (DKMS)",
		CurrentVersion:  currentAmneziaWGKernelVersion(),
		SourceRepo:      "amnezia-vpn/amneziawg-linux-kernel-module",
		SourceURL:       "https://github.com/amnezia-vpn/amneziawg-linux-kernel-module",
		UpdateAvailable: false,
		CanUpdate:       false,
		UpdateReason:    "The official repository currently has no Release assets with a publisher-provided SHA-256 digest. The installed source is vendored and DKMS-built for the host kernel; upgrading requires a reviewed source pin and kernel compatibility testing.",
	})

	tools := CoreVersionComponent{
		ID:             "awg-tools",
		Name:           "AmneziaWG Tools (awg / awg-quick)",
		CurrentVersion: currentAWGToolsVersion(),
		SourceRepo:     coreVersionAWGToolsRepo,
		SourceURL:      "https://github.com/" + coreVersionAWGToolsRepo,
		UpdateReason:   "Checking the official release metadata…",
	}
	release, err := s.fetchLatestAWGToolsRelease()
	if err != nil {
		tools.UpdateReason = "Could not verify the official release metadata: " + err.Error()
		if info.Warning == "" {
			info.Warning = tools.UpdateReason
		}
	} else {
		tools.LatestVersion = strings.TrimPrefix(strings.TrimSpace(release.TagName), "v")
		tools.ReleaseURL = release.HTMLURL
		tools.PublishedAt = release.PublishedAt
		asset, assetErr := selectAWGToolsAsset(release.Assets)
		if assetErr != nil {
			tools.UpdateReason = assetErr.Error()
		} else if _, digestErr := parseCoreVersionDigest(asset.Digest); digestErr != nil {
			tools.UpdateReason = "The official release asset has no valid SHA-256 digest; installation is disabled."
		} else {
			tools.AssetSHA256 = strings.TrimPrefix(asset.Digest, "sha256:")
			tools.Integrity = "GitHub release asset SHA-256 + per-file SHA-256 sidecars"
			supported, reason := awgToolsPlatformSupported()
			tools.UpdateAvailable = tools.CurrentVersion == "" || tools.CurrentVersion != tools.LatestVersion
			tools.CanUpdate = supported && tools.UpdateAvailable
			switch {
			case !supported:
				tools.UpdateReason = reason
			case !tools.UpdateAvailable:
				tools.UpdateReason = "The installed version is already current."
			default:
				tools.UpdateReason = "Ready: the official Ubuntu 22.04 x86-64 package includes per-file SHA-256 checksums."
			}
		}
	}
	info.Components = append(info.Components, tools)
	info.Backups = s.ListBackups()
	return info
}

func currentXrayVersion() string {
	bin := xray.GetBinaryPath()
	if _, err := os.Stat(bin); err != nil {
		return ""
	}
	out, err := exec.Command(bin, "-version").CombinedOutput()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return ""
	}
	return strings.TrimSpace(fields[1])
}

func currentAWGToolsVersion() string {
	p, err := exec.LookPath("awg")
	if err != nil {
		return ""
	}
	out, err := exec.Command(p, "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	m := awgToolsVersionPattern.FindStringSubmatch(string(out))
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

func currentAmneziaWGKernelVersion() string {
	if out, err := exec.Command("modinfo", "-F", "version", "amneziawg").Output(); err == nil {
		if v := strings.TrimSpace(string(out)); v != "" {
			return v
		}
	}
	// DKMS package version (not the in-module wireguard version).
	return awgsrc.Version + " (DKMS)"
}

func (s *CoreVersionManagerService) fetchLatestAWGToolsRelease() (*coreVersionRelease, error) {
	req, err := http.NewRequest(http.MethodGet, coreVersionAWGToolsAPI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vpn-ui-core-version-manager")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := s.httpClient("api.github.com").Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, coreVersionMaxAPIBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > coreVersionMaxAPIBytes {
		return nil, fmt.Errorf("release metadata exceeded the size limit")
	}
	var release coreVersionRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, fmt.Errorf("invalid GitHub release metadata: %w", err)
	}
	if release.TagName == "" || !strings.HasPrefix(release.HTMLURL, "https://github.com/"+coreVersionAWGToolsRepo+"/releases/") {
		return nil, fmt.Errorf("GitHub returned an unexpected release identity")
	}
	return &release, nil
}

func selectAWGToolsAsset(assets []coreVersionAsset) (coreVersionAsset, error) {
	for _, a := range assets {
		if a.Name == coreVersionAWGToolsAsset {
			if a.Size <= 0 || a.Size > coreVersionMaxAssetBytes {
				return coreVersionAsset{}, fmt.Errorf("the official AWG Tools package has an unexpected size")
			}
			return a, nil
		}
	}
	return coreVersionAsset{}, fmt.Errorf("the official release has no %s asset for this platform", coreVersionAWGToolsAsset)
}

// validateAWGToolsAssetURL binds the download URL to the official repository,
// exact release tag and expected asset name. No user-supplied URL is ever used.
func validateAWGToolsAssetURL(rawURL, tag, name string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("the release asset URL is not a trusted HTTPS GitHub URL")
	}
	want := "/"+coreVersionAWGToolsRepo+"/releases/download/"+tag+"/"+name
	if u.EscapedPath() != want || path.Clean(u.Path) != u.Path {
		return fmt.Errorf("the release asset URL does not match the official release")
	}
	return nil
}

func parseCoreVersionDigest(value string) (string, error) {
	algorithm, digest, ok := strings.Cut(strings.TrimSpace(value), ":")
	if !ok || strings.ToLower(algorithm) != "sha256" || !coreVersionHexPattern.MatchString(digest) {
		return "", fmt.Errorf("missing or invalid SHA-256 digest")
	}
	return strings.ToLower(digest), nil
}

func awgToolsPlatformSupported() (bool, string) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return false, "The published AWG Tools binary is for Linux x86-64 only."
	}
	id := strings.ToLower(strings.TrimSpace(osReleaseField("ID")))
	if id != "ubuntu" && id != "debian" {
		return false, "The published binary is built on Ubuntu 22.04; automatic installation is enabled only on Ubuntu/Debian systems with glibc 2.35 or newer."
	}
	if !commandExists("bash") {
		return false, "Bash is required by awg-quick but is not installed."
	}
	// The update is installed under /usr/local/bin to preserve distro-owned
	// files. It must actually win PATH lookup after installation, otherwise the
	// panel could keep launching the older /usr/bin copy.
	paths := filepath.SplitList(os.Getenv("PATH"))
	localIndex := -1
	for i, entry := range paths {
		if filepath.Clean(entry) == "/usr/local/bin" {
			localIndex = i
			break
		}
	}
	if localIndex < 0 {
		return false, "The panel process PATH does not include /usr/local/bin; refusing to install a binary that would not be selected."
	}
	for _, name := range []string{"awg", "awg-quick"} {
		if current, err := exec.LookPath(name); err == nil {
			if filepath.Dir(current) != "/usr/local/bin" {
				for i, entry := range paths {
					if filepath.Clean(entry) == filepath.Dir(current) && i < localIndex {
						return false, fmt.Sprintf("%s is resolved from %s before /usr/local/bin; refusing to shadow the active binary.", name, filepath.Dir(current))
					}
				}
			}
		}
	}
	for _, name := range []string{"awg", "awg-quick"} {
		target := filepath.Join("/usr/local/bin", name)
		if st, err := os.Lstat(target); err == nil && st.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Sprintf("%s is a symlink; refusing to replace it automatically.", target)
		}
	}
	out, err := exec.Command("getconf", "GNU_LIBC_VERSION").Output()
	if err != nil {
		return false, "Could not verify the host glibc version; automatic installation is disabled."
	}
	m := glibcVersionPattern.FindStringSubmatch(strings.TrimSpace(string(out)))
	if len(m) != 3 {
		return false, "Could not parse the host glibc version; automatic installation is disabled."
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	if major < 2 || (major == 2 && minor < 35) {
		return false, fmt.Sprintf("The published package requires glibc 2.35 or newer; this host has glibc %d.%d.", major, minor)
	}
	return true, ""
}

// InstallLatestAWGTools downloads the allowlisted official release, verifies the
// GitHub asset digest and the archive's individual file checksums, snapshots the
// existing /usr/local/bin files, then atomically installs and smoke-tests them.
func (s *CoreVersionManagerService) InstallLatestAWGTools() (*CoreVersionUpdateResult, error) {
	if !coreVersionUpdateMu.TryLock() {
		return nil, fmt.Errorf("another core version operation is already running")
	}
	defer coreVersionUpdateMu.Unlock()
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("updating core tools requires root privileges")
	}
	if ok, reason := awgToolsPlatformSupported(); !ok {
		return nil, fmt.Errorf("%s", reason)
	}

	release, err := s.fetchLatestAWGToolsRelease()
	if err != nil {
		return nil, err
	}
	asset, err := selectAWGToolsAsset(release.Assets)
	if err != nil {
		return nil, err
	}
	if err := validateAWGToolsAssetURL(asset.BrowserDownloadURL, release.TagName, asset.Name); err != nil {
		return nil, err
	}
	expectedDigest, err := parseCoreVersionDigest(asset.Digest)
	if err != nil {
		return nil, fmt.Errorf("refusing to install an asset without a trusted SHA-256 digest: %w", err)
	}
	targetVersion := strings.TrimPrefix(strings.TrimSpace(release.TagName), "v")
	currentVersion := currentAWGToolsVersion()
	if currentVersion == targetVersion {
		return nil, fmt.Errorf("AmneziaWG Tools %s is already installed", targetVersion)
	}

	archive, err := s.downloadAWGToolsAsset(asset)
	if err != nil {
		return nil, err
	}
	actual := sha256.Sum256(archive)
	if !strings.EqualFold(hex.EncodeToString(actual[:]), expectedDigest) {
		return nil, fmt.Errorf("release archive SHA-256 mismatch: expected %s, got %x", expectedDigest, actual)
	}
	payload, err := extractAWGToolsPayload(archive)
	if err != nil {
		return nil, err
	}
	if err := validateAWGToolsPayload(payload); err != nil {
		return nil, err
	}
	return s.installAWGToolsPayload(payload, currentVersion, targetVersion)
}

func (s *CoreVersionManagerService) downloadAWGToolsAsset(asset coreVersionAsset) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, asset.BrowserDownloadURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "vpn-ui-core-version-manager")
	resp, err := s.httpClient(
		"github.com",
		"release-assets.githubusercontent.com",
		"objects.githubusercontent.com",
		"github-releases.githubusercontent.com",
	).Do(req)
	if err != nil {
		return nil, fmt.Errorf("downloading the official AWG Tools package failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub release download returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > coreVersionMaxAssetBytes {
		return nil, fmt.Errorf("release package exceeds the configured size limit")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, coreVersionMaxAssetBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || len(body) > coreVersionMaxAssetBytes {
		return nil, fmt.Errorf("release package is empty or exceeds the configured size limit")
	}
	if asset.Size > 0 && int64(len(body)) != asset.Size {
		return nil, fmt.Errorf("release package size mismatch: expected %d bytes, got %d", asset.Size, len(body))
	}
	return body, nil
}

// extractAWGToolsPayload accepts only the two expected files and their publisher
// SHA-256 sidecars under the exact release archive directory. It rejects path
// traversal, links, duplicate entries, unknown files and oversized members.
func extractAWGToolsPayload(data []byte) (awgToolsPayload, error) {
	var payload awgToolsPayload
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return payload, fmt.Errorf("invalid AWG Tools ZIP archive: %w", err)
	}
	files := make(map[string][]byte, 4)
	total := uint64(0)
	for _, f := range reader.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		if strings.HasPrefix(name, "/") || strings.Contains(name, ":") {
			return payload, fmt.Errorf("unsafe path in AWG Tools archive")
		}
		clean := path.Clean(name)
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != name && strings.TrimSuffix(name, "/") != clean {
			return payload, fmt.Errorf("path traversal entry in AWG Tools archive")
		}
		if f.FileInfo().IsDir() {
			if clean != coreVersionAWGToolsArchiveDir {
				return payload, fmt.Errorf("unexpected directory in AWG Tools archive")
			}
			continue
		}
		if f.Mode()&os.ModeSymlink != 0 || f.Mode()&os.ModeType != 0 {
			return payload, fmt.Errorf("links and special files are not allowed in AWG Tools archive")
		}
		if !strings.HasPrefix(clean, coreVersionAWGToolsArchiveDir+"/") {
			return payload, fmt.Errorf("unexpected file path in AWG Tools archive")
		}
		base := strings.TrimPrefix(clean, coreVersionAWGToolsArchiveDir+"/")
		switch base {
		case "awg", "awg-quick", "awg.sha256", "awg-quick.sha256":
		default:
			return payload, fmt.Errorf("unexpected file %q in AWG Tools archive", base)
		}
		if _, exists := files[base]; exists {
			return payload, fmt.Errorf("duplicate file %q in AWG Tools archive", base)
		}
		if f.UncompressedSize64 == 0 || f.UncompressedSize64 > coreVersionMaxFileBytes {
			return payload, fmt.Errorf("file %q has an invalid size", base)
		}
		total += f.UncompressedSize64
		if total > 2*coreVersionMaxFileBytes {
			return payload, fmt.Errorf("AWG Tools archive expands beyond the size limit")
		}
		rc, err := f.Open()
		if err != nil {
			return payload, err
		}
		content, readErr := io.ReadAll(io.LimitReader(rc, coreVersionMaxFileBytes+1))
		_ = rc.Close()
		if readErr != nil {
			return payload, readErr
		}
		if len(content) == 0 || len(content) > coreVersionMaxFileBytes || uint64(len(content)) != f.UncompressedSize64 {
			return payload, fmt.Errorf("file %q failed its size check", base)
		}
		files[base] = content
	}
	for _, name := range []string{"awg", "awg-quick", "awg.sha256", "awg-quick.sha256"} {
		if _, ok := files[name]; !ok {
			return payload, fmt.Errorf("AWG Tools archive is missing %s", name)
		}
	}
	if err := verifySidecar(files["awg"], files["awg.sha256"]); err != nil {
		return payload, fmt.Errorf("awg file checksum failed: %w", err)
	}
	if err := verifySidecar(files["awg-quick"], files["awg-quick.sha256"]); err != nil {
		return payload, fmt.Errorf("awg-quick file checksum failed: %w", err)
	}
	payload.AWG = files["awg"]
	payload.AWGQuick = files["awg-quick"]
	return payload, nil
}

func verifySidecar(data, sidecar []byte) error {
	fields := strings.Fields(string(sidecar))
	if len(fields) != 1 || !coreVersionHexPattern.MatchString(fields[0]) {
		return fmt.Errorf("invalid SHA-256 sidecar")
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), fields[0]) {
		return fmt.Errorf("SHA-256 mismatch")
	}
	return nil
}

func validateAWGToolsPayload(payload awgToolsPayload) error {
	f, err := elf.NewFile(bytes.NewReader(payload.AWG))
	if err != nil {
		return fmt.Errorf("the awg package member is not a valid ELF executable: %w", err)
	}
	_ = f.Close()
	if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 {
		return fmt.Errorf("the awg executable is not a Linux x86-64 binary")
	}
	if !bytes.HasPrefix(payload.AWGQuick, []byte("#!")) || bytes.IndexByte(payload.AWGQuick, 0) >= 0 {
		return fmt.Errorf("the awg-quick package member is not a valid shell script")
	}
	tmp, err := os.CreateTemp("", "vpn-ui-awg-quick-*.sh")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(payload.AWGQuick); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if out, err := exec.Command("bash", "-n", name).CombinedOutput(); err != nil {
		return fmt.Errorf("awg-quick syntax check failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *CoreVersionManagerService) installAWGToolsPayload(payload awgToolsPayload, fromVersion, toVersion string) (*CoreVersionUpdateResult, error) {
	dir := s.installPath()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	backup, err := s.createAWGToolsBackup(fromVersion, toVersion)
	if err != nil {
		return nil, fmt.Errorf("backup failed; nothing was changed: %w", err)
	}
	for _, item := range []struct {
		name string
		data []byte
	}{
		{name: "awg", data: payload.AWG},
		{name: "awg-quick", data: payload.AWGQuick},
	} {
		if err := writeCoreVersionAtomically(filepath.Join(dir, item.name), item.data, 0755); err != nil {
			_ = s.restoreAWGToolsBackup(backup)
			return nil, fmt.Errorf("installing %s failed; previous files were restored: %w", item.name, err)
		}
	}
	if err := s.validateInstalledAWGTools(toVersion); err != nil {
		restoreErr := s.restoreAWGToolsBackup(backup)
		if restoreErr != nil {
			return nil, fmt.Errorf("new AWG Tools failed its health check (%v) and automatic restore failed (%v); backup: %s", err, restoreErr, backup.ID)
		}
		return nil, fmt.Errorf("new AWG Tools failed its health check; previous files were restored: %w", err)
	}
	s.pruneBackups()
	return &CoreVersionUpdateResult{
		Component:   "awg-tools",
		FromVersion: firstNonEmptyCoreVersion(fromVersion, "not installed"),
		ToVersion:   toVersion,
		BackupID:    backup.ID,
		UpdatedAt:   time.Now().UTC(),
	}, nil
}

func (s *CoreVersionManagerService) validateInstalledAWGTools(expectedVersion string) error {
	awgPath := filepath.Join(s.installPath(), "awg")
	out, err := exec.Command(awgPath, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("awg --version failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	m := awgToolsVersionPattern.FindStringSubmatch(string(out))
	if len(m) != 2 || m[1] != expectedVersion {
		return fmt.Errorf("installed awg version mismatch: expected %s, got %s", expectedVersion, strings.TrimSpace(string(out)))
	}
	quickPath := filepath.Join(s.installPath(), "awg-quick")
	if out, err := exec.Command("bash", "-n", quickPath).CombinedOutput(); err != nil {
		return fmt.Errorf("installed awg-quick failed its syntax check: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *CoreVersionManagerService) createAWGToolsBackup(fromVersion, toVersion string) (*coreVersionBackupManifest, error) {
	id := time.Now().UTC().Format("20060102T150405.000000000Z")
	root := s.backupPath()
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("backup root must be a real directory")
	}
	if err := os.Chmod(root, 0700); err != nil {
		return nil, err
	}
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0700); err != nil {
		return nil, err
	}
	manifest := &coreVersionBackupManifest{
		ID:          id,
		Component:   "awg-tools",
		FromVersion: fromVersion,
		ToVersion:   toVersion,
		CreatedAt:   time.Now().UTC(),
		Files:       make([]coreVersionBackupFile, 0, 2),
	}
	for _, name := range []string{"awg", "awg-quick"} {
		target := filepath.Join(s.installPath(), name)
		entry := coreVersionBackupFile{Name: name}
		st, err := os.Lstat(target)
		switch {
		case errors.Is(err, os.ErrNotExist):
			// The absence is part of the snapshot: rollback removes a newly-created file.
		case err != nil:
			return nil, err
		case st.Mode()&os.ModeSymlink != 0:
			return nil, fmt.Errorf("refusing to replace symlink %s", target)
		case !st.Mode().IsRegular():
			return nil, fmt.Errorf("refusing to replace non-regular file %s", target)
		default:
			data, err := os.ReadFile(target)
			if err != nil {
				return nil, err
			}
			entry.Existed = true
			entry.Mode = uint32(st.Mode().Perm())
			sum := sha256.Sum256(data)
			entry.SHA256 = hex.EncodeToString(sum[:])
			if err := writeCoreVersionAtomically(filepath.Join(dir, "files", name), data, 0600); err != nil {
				return nil, err
			}
		}
		manifest.Files = append(manifest.Files, entry)
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeCoreVersionAtomically(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
		return nil, err
	}
	return manifest, nil
}

func (s *CoreVersionManagerService) restoreAWGToolsBackup(manifest *coreVersionBackupManifest) error {
	if manifest == nil || manifest.Component != "awg-tools" || !coreVersionIDPattern.MatchString(manifest.ID) {
		return fmt.Errorf("invalid AWG Tools backup manifest")
	}
	dir := filepath.Join(s.backupPath(), manifest.ID, "files")
	for _, entry := range manifest.Files {
		if entry.Name != "awg" && entry.Name != "awg-quick" {
			return fmt.Errorf("backup contains an unexpected file")
		}
		target := filepath.Join(s.installPath(), entry.Name)
		if !entry.Existed {
			if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), entry.SHA256) {
			return fmt.Errorf("backup checksum mismatch for %s", entry.Name)
		}
		mode := os.FileMode(entry.Mode) & 0777
		if mode == 0 {
			mode = 0755
		}
		if err := writeCoreVersionAtomically(target, data, mode); err != nil {
			return err
		}
	}
	return nil
}

func (s *CoreVersionManagerService) RollbackAWGTools(backupID string) (*CoreVersionUpdateResult, error) {
	if !coreVersionUpdateMu.TryLock() {
		return nil, fmt.Errorf("another core version operation is already running")
	}
	defer coreVersionUpdateMu.Unlock()
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("rollback requires root privileges")
	}
	if !coreVersionIDPattern.MatchString(backupID) || backupID == "." || backupID == ".." || filepath.Base(backupID) != backupID {
		return nil, fmt.Errorf("invalid backup identifier")
	}
	manifestPath := filepath.Join(s.backupPath(), backupID, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading backup manifest: %w", err)
	}
	var manifest coreVersionBackupManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("invalid backup manifest: %w", err)
	}
	if manifest.ID != backupID || manifest.Component != "awg-tools" {
		return nil, fmt.Errorf("backup does not belong to AmneziaWG Tools")
	}
	fromVersion := currentAWGToolsVersion()
	safety, err := s.createAWGToolsBackup(fromVersion, "rollback-safety")
	if err != nil {
		return nil, fmt.Errorf("could not snapshot the current files before rollback: %w", err)
	}
	if err := s.restoreAWGToolsBackup(&manifest); err != nil {
		_ = s.restoreAWGToolsBackup(safety)
		return nil, fmt.Errorf("rollback failed; the pre-rollback state was restored: %w", err)
	}
	if err := s.validateRolledBackAWGTools(); err != nil {
		restoreErr := s.restoreAWGToolsBackup(safety)
		if restoreErr != nil {
			return nil, fmt.Errorf("rollback health check failed (%v) and safety restore failed (%v); safety backup: %s", err, restoreErr, safety.ID)
		}
		return nil, fmt.Errorf("rollback health check failed; the pre-rollback state was restored: %w", err)
	}
	s.pruneBackups()
	return &CoreVersionUpdateResult{
		Component:   "awg-tools",
		FromVersion: firstNonEmptyCoreVersion(fromVersion, "unknown"),
		ToVersion:   manifest.FromVersion,
		BackupID:    safety.ID,
		UpdatedAt:   time.Now().UTC(),
	}, nil
}

func (s *CoreVersionManagerService) validateRolledBackAWGTools() error {
	awgPath := filepath.Join(s.installPath(), "awg")
	if _, err := os.Stat(awgPath); errors.Is(err, os.ErrNotExist) {
		// No locally-installed copy is a valid rollback state; the distro copy, if
		// any, remains untouched and will again be resolved through PATH.
		return nil
	}
	out, err := exec.Command(awgPath, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("restored awg --version failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	quickPath := filepath.Join(s.installPath(), "awg-quick")
	if _, err := os.Stat(quickPath); err == nil {
		if out, err := exec.Command("bash", "-n", quickPath).CombinedOutput(); err != nil {
			return fmt.Errorf("restored awg-quick failed its syntax check: %v (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (s *CoreVersionManagerService) ListBackups() []CoreVersionBackupInfo {
	entries, err := os.ReadDir(s.backupPath())
	if err != nil {
		return nil
	}
	out := make([]CoreVersionBackupInfo, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !coreVersionIDPattern.MatchString(entry.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.backupPath(), entry.Name(), "manifest.json"))
		if err != nil {
			continue
		}
		var m coreVersionBackupManifest
		if err := json.Unmarshal(raw, &m); err != nil || m.ID != entry.Name() || m.Component != "awg-tools" {
			continue
		}
		out = append(out, CoreVersionBackupInfo{
			ID: m.ID, Component: m.Component, FromVersion: m.FromVersion,
			ToVersion: m.ToVersion, CreatedAt: m.CreatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *CoreVersionManagerService) pruneBackups() {
	backups := s.ListBackups()
	for _, item := range backups[coreVersionBackupRetention:] {
		if coreVersionIDPattern.MatchString(item.ID) {
			_ = os.RemoveAll(filepath.Join(s.backupPath(), item.ID))
		}
	}
}

func writeCoreVersionAtomically(dest string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dest)+".new-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func firstNonEmptyCoreVersion(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
