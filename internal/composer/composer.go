// Package composer confirms files of Composer packages against the archives
// they were installed from.
//
// vendor/composer/installed.json names every package with the commit it was
// built from. The register the maintainers publish to, repo.packagist.org,
// names the archive of that commit. A file below a package that is byte for
// byte the one in that archive is the package's own, whatever a rule thinks
// of its content: the test files of PHP_CodeSniffer, the PHAR of Zend's
// scaffolder, the CA bundle of composer/ca-bundle. The archive of a commit
// never changes, so its sums are kept for good once loaded.
//
// The address of the archive in installed.json is not used: whoever can write
// a file of the website can write that one too, and point it at an archive of
// their own making.
package composer

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Defaults of the settings. The ISPConfig addon has the same values as the
// defaults of its settings (malwatch_config verify_*).
var DefaultHosts = []string{"codeload.github.com", "api.github.com", "github.com", "gitlab.com", "bitbucket.org"}

const (
	DefaultMaxDownloads   = 50
	DefaultMaxMB          = 50
	DefaultTimeoutSeconds = 60
	DefaultRetryHours     = 24
	// DefaultPackagistURL is the register of Composer packages, as Composer
	// itself asks it (malwatch_config verify_packagist_url).
	DefaultPackagistURL = "https://repo.packagist.org"
)

// CheckPackagistURL says in German why the address of a register cannot be
// used, or returns nil. The address travels on the command line of the
// scanner, where every user of the server can read it, so a login in it is
// refused and shown masked.
func CheckPackagistURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("die Adresse des Paketregisters ist nicht lesbar; erwartet wird eine https-Adresse wie %s",
			DefaultPackagistURL)
	}
	if u.User != nil {
		return fmt.Errorf("die Adresse %s enthält Anmeldedaten. Sie steht auf der Befehlszeile des Scanners, "+
			"die jeder Benutzer des Servers lesen kann; bitte eine Adresse ohne Benutzer und Passwort angeben",
			u.Redacted())
	}
	if u.Scheme != "https" || u.Host == "" || len(raw) > 200 {
		return fmt.Errorf("%q ist keine https-Adresse wie %s", raw, DefaultPackagistURL)
	}
	return nil
}

// Limits of the settings.
const (
	MaxHosts        = 16
	MaxHostLength   = 100
	MaxDownloadsCap = 1000
	MaxMBCap        = 500
	MaxTimeoutCap   = 600
	MaxRetryCap     = 720
)

var hostName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$`)

// CheckHosts says in German why a list of hosts cannot be used, or returns nil.
func CheckHosts(hosts []string) error {
	if len(hosts) > MaxHosts {
		return fmt.Errorf("%d Hosts angegeben, erlaubt sind höchstens %d", len(hosts), MaxHosts)
	}
	for _, h := range hosts {
		if len(h) > MaxHostLength || !hostName.MatchString(h) {
			return fmt.Errorf("der Host %q geht nicht: nur ein Name wie codeload.github.com, ohne https:// und "+
				"ohne Pfad, bis zu %d Zeichen", h, MaxHostLength)
		}
	}
	return nil
}

// Package is one installed package with the archive it came from.
type Package struct {
	Name      string
	Version   string
	URL       string
	Reference string
	// Dir is the directory the package is installed in.
	Dir string
}

var packageName = regexp.MustCompile(`^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*$`)

type installedPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dist    struct {
		Type      string `json:"type"`
		URL       string `json:"url"`
		Reference string `json:"reference"`
	} `json:"dist"`
	InstallPath string `json:"install-path"`
}

// Installed reads the packages of a vendor directory from its
// composer/installed.json, in the format of Composer 1 (a list) or 2 (an
// object with packages). Packages without a zip archive are left out, and so
// is one whose install path leaves the project.
func Installed(vendor string) ([]Package, error) {
	f, err := os.Open(filepath.Join(vendor, "composer", "installed.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 32*1024*1024))
	if err != nil {
		return nil, err
	}
	var list []installedPackage
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, err
		}
	} else {
		var doc struct {
			Packages []installedPackage `json:"packages"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		list = doc.Packages
	}

	project := filepath.Dir(filepath.Clean(vendor))
	var out []Package
	for _, p := range list {
		if !packageName.MatchString(p.Name) || p.Dist.Type != "zip" || p.Dist.URL == "" {
			continue
		}
		dir := filepath.Join(vendor, filepath.FromSlash(p.Name))
		if p.InstallPath != "" {
			dir = filepath.Join(vendor, "composer", filepath.FromSlash(p.InstallPath))
		}
		dir = filepath.Clean(dir)
		if rel, err := filepath.Rel(project, dir); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		out = append(out, Package{Name: p.Name, Version: p.Version, URL: p.Dist.URL, Reference: p.Dist.Reference, Dir: dir})
	}
	return out, nil
}

// Options steer the fetcher.
type Options struct {
	// CacheDir keeps the sums of loaded archives and the marks of failed
	// ones; empty keeps nothing.
	CacheDir string
	// Hosts are the only hosts an archive is loaded from.
	Hosts []string
	// MaxDownloads caps the archives one run loads.
	MaxDownloads int
	// MaxMB caps the size of one archive; unpacked it may hold ten times as
	// much.
	MaxMB int
	// Timeout caps one download.
	Timeout time.Duration
	// RetryHours is how long a failed archive is not asked for again.
	RetryHours int
	// PackagistURL is the register that names the archive of every commit,
	// such as https://repo.packagist.org; empty confirms nothing.
	PackagistURL string
	// Transport replaces the network for the tests; nil is the default.
	Transport http.RoundTripper
}

// Fetcher loads archives and returns the SHA-256 of every file in them.
type Fetcher struct {
	opts      Options
	hosts     map[string]bool
	client    *http.Client
	downloads int
	failures  []string
	// asked holds the files of the register loaded in this run.
	asked map[string]bool
}

// NewFetcher returns a fetcher for opts.
func NewFetcher(opts Options) *Fetcher {
	f := &Fetcher{opts: opts, hosts: map[string]bool{}}
	for _, h := range opts.Hosts {
		f.hosts[strings.ToLower(h)] = true
	}
	f.client = &http.Client{
		Timeout:   opts.Timeout,
		Transport: opts.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("zu viele Weiterleitungen")
			}
			if !f.hosts[strings.ToLower(req.URL.Hostname())] {
				return fmt.Errorf("Weiterleitung zu %s, der nicht in der Liste der Hosts steht", req.URL.Hostname())
			}
			return nil
		},
	}
	return f
}

// Failures lists the archives that could not be loaded in this run.
func (f *Fetcher) Failures() []string { return f.failures }

// Published returns the address of the archive the register lists for package
// name at reference, the commit the website says it installed. A reference the
// register does not list confirms nothing: a package of the website's own, or
// an address someone put into installed.json. Tagged versions and development
// branches stand in two files of the register; both are asked.
func (f *Fetcher) Published(name, version, reference string) (string, error) {
	if f.opts.PackagistURL == "" {
		return "", errors.New("kein Paketregister eingestellt")
	}
	name = strings.ToLower(name)
	if !packageName.MatchString(name) || reference == "" {
		return "", fmt.Errorf("%s: kein Paket mit Stand", name)
	}
	files := []string{name + ".json", name + "~dev.json"}
	if strings.HasPrefix(version, "dev-") || strings.HasSuffix(version, "-dev") {
		files[0], files[1] = files[1], files[0]
	}
	for _, file := range files {
		dists, err := f.register(file, name, reference)
		if err != nil {
			return "", err
		}
		for _, d := range dists {
			if d.URL != "" && strings.EqualFold(d.Reference, reference) {
				return d.URL, nil
			}
		}
	}
	return "", fmt.Errorf("%s: das Paketregister kennt den Stand %s nicht", name, reference)
}

// dist is the archive of one version in the register.
type dist struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
}

// register returns the archives one file of the register lists for name. The
// copy in the cache serves as long as it lists reference; a reference it lacks
// is asked for anew once a run, since a new version may have come out since.
// A package the register does not know is no failure, only no confirmation.
func (f *Fetcher) register(file, name, reference string) ([]dist, error) {
	key := cacheKey("packagist", file)
	if raw, err := os.ReadFile(f.cachePath(key, ".register")); err == nil && f.cachePath(key, ".register") != "" {
		if dists, err := parseRegister(raw, name); err == nil && (listsReference(dists, reference) || f.asked[file]) {
			return dists, nil
		}
	}
	if f.asked == nil {
		f.asked = map[string]bool{}
	}
	if f.asked[file] {
		return nil, nil
	}
	f.asked[file] = true
	if f.recentlyFailed(key) {
		return nil, fmt.Errorf("Paketregister für %s ist zuletzt gescheitert, nächster Versuch nach %d Stunden",
			name, f.opts.RetryHours)
	}
	if f.downloads >= f.opts.MaxDownloads {
		return nil, fmt.Errorf("die Grenze von %d Abrufen je Lauf ist erreicht", f.opts.MaxDownloads)
	}
	f.downloads++
	raw, found, err := f.fetchRegister(strings.TrimRight(f.opts.PackagistURL, "/") + "/p2/" + file)
	if err != nil {
		f.failures = append(f.failures, "Paketregister "+file+": "+err.Error())
		f.markFailed(key)
		return nil, err
	}
	if !found {
		return nil, nil
	}
	if p := f.cachePath(key, ".register"); p != "" && os.MkdirAll(f.opts.CacheDir, 0o750) == nil {
		tmp := p + ".tmp"
		if os.WriteFile(tmp, raw, 0o640) == nil {
			_ = os.Rename(tmp, p)
		}
	}
	return parseRegister(raw, name)
}

// fetchRegister loads one file of the register. found is false when the
// register answers that it has no such package.
func (f *Fetcher) fetchRegister(raw string) ([]byte, bool, error) {
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "malwatch")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	max := int64(f.opts.MaxMB) * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > max {
		return nil, false, fmt.Errorf("Antwort größer als %d MB", f.opts.MaxMB)
	}
	return body, true, nil
}

// parseRegister reads the archives of name from a file of the register. In the
// minified form every entry lists what changed against the one before, and
// "__unset" removes a field.
func parseRegister(raw []byte, name string) ([]dist, error) {
	var doc struct {
		Minified string                                  `json:"minified"`
		Packages map[string][]map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("Antwort des Paketregisters nicht lesbar: %w", err)
	}
	var out []dist
	cur := map[string]json.RawMessage{}
	for _, entry := range doc.Packages[name] {
		if doc.Minified == "" {
			cur = map[string]json.RawMessage{}
		}
		for k, v := range entry {
			if string(v) == `"__unset"` {
				delete(cur, k)
			} else {
				cur[k] = v
			}
		}
		var d dist
		if v, ok := cur["dist"]; ok {
			_ = json.Unmarshal(v, &d)
		}
		out = append(out, d)
	}
	return out, nil
}

func listsReference(dists []dist, reference string) bool {
	for _, d := range dists {
		if d.URL != "" && strings.EqualFold(d.Reference, reference) {
			return true
		}
	}
	return false
}

// Files returns the SHA-256 of every file of the archive at distURL, by its
// path below the top directory of the archive.
func (f *Fetcher) Files(distURL, reference string) (map[string]string, error) {
	key := cacheKey(distURL, reference)
	if files, ok := f.cached(key); ok {
		return files, nil
	}
	if f.recentlyFailed(key) {
		return nil, fmt.Errorf("%s ist zuletzt gescheitert, nächster Versuch nach %d Stunden", distURL, f.opts.RetryHours)
	}
	if f.downloads >= f.opts.MaxDownloads {
		return nil, fmt.Errorf("die Grenze von %d Archiven je Lauf ist erreicht", f.opts.MaxDownloads)
	}
	files, err := f.load(downloadURL(distURL))
	if err != nil {
		f.failures = append(f.failures, "Composer-Archiv "+distURL+": "+err.Error())
		f.markFailed(key)
		return nil, err
	}
	f.store(key, files)
	return files, nil
}

// downloadURL takes the archive of a GitHub commit from codeload, where the
// API sends it anyway, so the download does not count against the API limit.
func downloadURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host != "api.github.com" {
		return raw
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) == 5 && parts[0] == "repos" && parts[3] == "zipball" {
		return "https://codeload.github.com/" + parts[1] + "/" + parts[2] + "/legacy.zip/" + parts[4]
	}
	return raw
}

// load downloads one archive and hashes its files.
func (f *Fetcher) load(raw string) (map[string]string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("keine https-Adresse: %s", raw)
	}
	if !f.hosts[strings.ToLower(u.Hostname())] {
		return nil, fmt.Errorf("%s steht nicht in der Liste der Hosts", u.Hostname())
	}
	f.downloads++

	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "malwatch")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	max := int64(f.opts.MaxMB) * 1024 * 1024
	if resp.ContentLength > max {
		return nil, fmt.Errorf("Archiv größer als %d MB", f.opts.MaxMB)
	}
	tmp, err := os.CreateTemp(f.tempDir(), "composer-*.zip")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if n > max {
		return nil, fmt.Errorf("Archiv größer als %d MB", f.opts.MaxMB)
	}
	return hashZip(tmp, n, 10*max)
}

func (f *Fetcher) tempDir() string {
	if f.opts.CacheDir != "" {
		if err := os.MkdirAll(f.opts.CacheDir, 0o750); err == nil {
			return f.opts.CacheDir
		}
	}
	return ""
}

// hashZip returns the SHA-256 of every file in the archive, by its path below
// the top directory the whole archive shares, as Composer unpacks it. At most
// limit bytes are read unpacked.
func hashZip(r io.ReaderAt, size, limit int64) (map[string]string, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("kein lesbares zip: %w", err)
	}
	top := ""
	for i, zf := range zr.File {
		first := strings.SplitN(zf.Name, "/", 2)[0]
		if i == 0 {
			top = first
		} else if first != top {
			top = ""
			break
		}
	}
	out := map[string]string{}
	var total int64
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		name := zf.Name
		if top != "" {
			name = strings.TrimPrefix(name, top+"/")
		}
		name = path.Clean(name)
		if name == "." || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		n, err := io.Copy(h, io.LimitReader(rc, limit-total+1))
		rc.Close()
		if err != nil {
			return nil, err
		}
		total += n
		if total > limit {
			return nil, errors.New("Archiv entpackt zu groß")
		}
		out[name] = hex.EncodeToString(h.Sum(nil))
	}
	return out, nil
}

func cacheKey(distURL, reference string) string {
	h := sha256.Sum256([]byte(distURL + "|" + reference))
	return hex.EncodeToString(h[:16])
}

func (f *Fetcher) cachePath(key, ext string) string {
	if f.opts.CacheDir == "" {
		return ""
	}
	return filepath.Join(f.opts.CacheDir, "composer-"+key+ext)
}

func (f *Fetcher) cached(key string) (map[string]string, bool) {
	p := f.cachePath(key, ".json")
	if p == "" {
		return nil, false
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var doc struct {
		Files map[string]string `json:"files"`
	}
	if json.Unmarshal(raw, &doc) != nil || len(doc.Files) == 0 {
		return nil, false
	}
	return doc.Files, true
}

func (f *Fetcher) store(key string, files map[string]string) {
	p := f.cachePath(key, ".json")
	if p == "" {
		return
	}
	raw, err := json.Marshal(map[string]any{"files": files})
	if err != nil {
		return
	}
	if err := os.MkdirAll(f.opts.CacheDir, 0o750); err != nil {
		return
	}
	tmp := p + ".tmp"
	if os.WriteFile(tmp, raw, 0o640) == nil {
		_ = os.Rename(tmp, p)
	}
	_ = os.Remove(f.cachePath(key, ".fail"))
}

func (f *Fetcher) recentlyFailed(key string) bool {
	p := f.cachePath(key, ".fail")
	if p == "" {
		return false
	}
	info, err := os.Stat(p)
	return err == nil && time.Since(info.ModTime()) < time.Duration(f.opts.RetryHours)*time.Hour
}

func (f *Fetcher) markFailed(key string) {
	p := f.cachePath(key, ".fail")
	if p == "" {
		return
	}
	if err := os.MkdirAll(f.opts.CacheDir, 0o750); err == nil {
		_ = os.WriteFile(p, nil, 0o640)
	}
}
