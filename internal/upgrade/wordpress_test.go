package upgrade

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestReadCoreReadsTheFourFacts(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "wp-includes", "version.php"),
		"<?php\n$wp_version = '6.4.5';\n$wp_db_version = 56657;\n"+
			"$required_php_version = '7.0.0';\n$wp_local_package = 'de_DE';\n")
	facts, err := ReadCore(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := CoreFacts{Version: "6.4.5", DBVersion: "56657", RequiredPHP: "7.0.0", Locale: "de_DE"}
	if facts != want {
		t.Errorf("facts = %+v, want %+v", facts, want)
	}
}

func TestPluginRequirementsPreferTheHeaderAndFallBackToTheReadme(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "kontakt")
	writeFile(t, filepath.Join(dir, "helpers.php"), "<?php // no header")
	writeFile(t, filepath.Join(dir, "kontakt.php"),
		"<?php\n/*\nPlugin Name: Kontakt\nVersion: 2.0\nRequires PHP: 8.1\n*/")
	writeFile(t, filepath.Join(dir, "readme.txt"),
		"=== Kontakt ===\nRequires at least: 6.5\nRequires PHP: 7.4\n")
	req, err := PluginRequirements(dir)
	if err != nil {
		t.Fatal(err)
	}
	if req.PHP != "8.1" || req.WordPress != "6.5" {
		t.Errorf("requirements = %+v, want PHP 8.1 from the header, WordPress 6.5 from the readme", req)
	}
}

func TestThemeRequirementsComeFromStyleCSS(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "style.css"),
		"/*\nTheme Name: Vier\nRequires at least: 6.4\nRequires PHP: 7.0\n*/")
	req, err := ThemeRequirements(dir)
	if err != nil || req.WordPress != "6.4" || req.PHP != "7.0" {
		t.Fatalf("requirements = %+v, %v", req, err)
	}
}

func TestRequirementsCheckNamesWhatIsMissing(t *testing.T) {
	req := Requirements{WordPress: "6.6", PHP: "8.1"}
	if got := req.Check("3.25.1", "6.6.2", "7.4.33"); got != "3.25.1 braucht PHP 8.1, die Website läuft mit 7.4.33" {
		t.Errorf("php: %q", got)
	}
	if got := req.Check("3.25.1", "6.4.5", "8.2.10"); got != "3.25.1 braucht WordPress 6.6, installiert ist 6.4.5" {
		t.Errorf("wordpress: %q", got)
	}
	if got := req.Check("3.25.1", "6.6", "8.1"); got != "" {
		t.Errorf("met requirements refused: %q", got)
	}
}

func TestMultisiteReadsTheConfigOrTheOneAbove(t *testing.T) {
	root := t.TempDir()
	inst := filepath.Join(root, "web")
	writeFile(t, filepath.Join(inst, "wp-includes", "version.php"), "<?php\n$wp_version = '6.4.5';\n")
	if Multisite(inst) {
		t.Fatal("an installation without wp-config.php counts as multisite")
	}
	writeFile(t, filepath.Join(root, "wp-config.php"), "<?php\ndefine( 'MULTISITE', true );\n")
	if !Multisite(inst) {
		t.Error("wp-config.php one directory up was not read")
	}
	writeFile(t, filepath.Join(inst, "wp-config.php"), "<?php\ndefine('WP_DEBUG', false);\n")
	if Multisite(inst) {
		t.Error("the installation's own wp-config.php has to win")
	}
}

func TestMaintenanceFollowsTheRulesOfWordPress(t *testing.T) {
	root := t.TempDir()
	now := time.Unix(1_790_000_000, 0)
	if MaintenanceActive(root, now) {
		t.Fatal("no file, yet active")
	}
	if err := EnterMaintenance(root, now); err != nil {
		t.Fatal(err)
	}
	if !MaintenanceActive(root, now.Add(time.Minute)) {
		t.Error("a fresh file is not active")
	}
	if MaintenanceActive(root, now.Add(11*time.Minute)) {
		t.Error("a file WordPress ignores counts as active")
	}
	if err := LeaveMaintenance(root); err != nil {
		t.Fatal(err)
	}
	if err := LeaveMaintenance(root); err != nil {
		t.Errorf("leaving twice: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".maintenance")); !os.IsNotExist(err) {
		t.Error("the file is still there")
	}
}

func TestEnterMaintenanceRefusesALink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need extra rights on Windows")
	}
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Symlink(target, filepath.Join(root, ".maintenance")); err != nil {
		t.Fatal(err)
	}
	if err := EnterMaintenance(root, time.Now()); err == nil {
		t.Fatal("a link was written through")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Error("the link target was created")
	}
}
