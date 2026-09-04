package cms

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Plugin and theme headers live in a comment block at the top of the main
// file. WordPress itself only reads the first 8 KB, so neither do we.
const headerBytes = 8192

var (
	pluginNameRe = regexp.MustCompile(`(?im)^[ \t/*#@]*Plugin Name\s*:\s*(.+)$`)
	themeNameRe  = regexp.MustCompile(`(?im)^[ \t/*#@]*Theme Name\s*:\s*(.+)$`)
	versionRe    = regexp.MustCompile(`(?im)^[ \t/*#@]*Version\s*:\s*(.+)$`)
)

// wordpressExtras lists the plugins and themes of an installation.
func wordpressExtras(root string) []Install {
	contentDir := wpContentDir(root)
	if contentDir == "" {
		return nil
	}
	var out []Install
	out = append(out, wpPlugins(filepath.Join(contentDir, "plugins"))...)
	out = append(out, wpThemes(filepath.Join(contentDir, "themes"))...)
	return out
}

// wpContentDir finds the content directory, which a site may have renamed.
func wpContentDir(root string) string {
	if dir := filepath.Join(root, "wp-content"); isDir(dir) {
		return dir
	}
	// A renamed content directory is recognised by holding both plugins and
	// themes right below the web root.
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		if isDir(filepath.Join(dir, "plugins")) && isDir(filepath.Join(dir, "themes")) {
			return dir
		}
	}
	return ""
}

// wpPlugins reads every plugin directory. The version comes from the file
// that carries the "Plugin Name" header, which is what WordPress uses too.
func wpPlugins(dir string) []Install {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Install
	for _, e := range entries {
		if !e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		slug := e.Name()
		pluginDir := filepath.Join(dir, slug)
		name, version := headerOf(pluginDir, pluginNameRe)
		if version == "" {
			continue
		}
		_ = name
		out = append(out, Install{
			Path:    pluginDir,
			Product: "wordpress",
			Kind:    "plugin",
			Slug:    slug,
			Version: version,
		})
	}
	return out
}

// wpThemes reads every theme directory; the header sits in style.css.
func wpThemes(dir string) []Install {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Install
	for _, e := range entries {
		if !e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		slug := e.Name()
		style := filepath.Join(dir, slug, "style.css")
		head, err := readHead(style, headerBytes)
		if err != nil {
			continue
		}
		if !themeNameRe.Match(head) {
			continue
		}
		v := firstGroup(versionRe, head)
		if v == "" {
			continue
		}
		out = append(out, Install{
			Path:    filepath.Join(dir, slug),
			Product: "wordpress",
			Kind:    "theme",
			Slug:    slug,
			Version: v,
		})
	}
	return out
}

// headerOf scans the PHP files directly inside dir for a plugin header.
func headerOf(dir string, nameRe *regexp.Regexp) (string, string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", ""
	}
	// The main file usually carries the directory name; try it first so a
	// bundled sub-plugin does not win over the real one.
	preferred := filepath.Base(dir) + ".php"
	files := make([]string, 0, len(entries)+1)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".php") {
			continue
		}
		if e.Name() == preferred {
			files = append([]string{e.Name()}, files...)
			continue
		}
		files = append(files, e.Name())
	}
	for _, f := range files {
		head, err := readHead(filepath.Join(dir, f), headerBytes)
		if err != nil {
			continue
		}
		name := firstGroup(nameRe, head)
		if name == "" {
			continue
		}
		return name, firstGroup(versionRe, head)
	}
	return "", ""
}

func firstGroup(re *regexp.Regexp, content []byte) string {
	m := re.FindSubmatch(content)
	if m == nil {
		return ""
	}
	// Strip trailing comment markers that plugin authors leave on the line.
	v := strings.TrimSpace(string(m[1]))
	v = strings.TrimRight(v, " \t*/")
	return strings.TrimSpace(v)
}

func readHead(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	read, err := f.Read(buf)
	if err != nil && read == 0 {
		return nil, err
	}
	return buf[:read], nil
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
