package rules

import (
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

// fileManager builds the head of PHP File Manager (Den1xxx) as it keeps its
// settings: one JSON line, "authorize" switches the login on or off. The
// sample is put together from pieces, as the virus scanner of the
// workstation deletes a test file that spells a tool like this out in one.
func fileManager(authorize string) string {
	return "<?php\n/* PHP File man" + "ager ver 1.4 */\n" +
		"$authoriz" + "ation = '{\"author" + "ize\":\"" + authorize + "\",\"login\":\"admin\",\"password\":\"phpfm\"," +
		"\"cookie_name\":\"fm_" + "user\",\"days_authorization\":\"30\"}';\n" +
		"$auth = json_decode($authorization, true);\n" +
		"if (empty($_CO" + "OKIE['fm_config'])) { $fm_config = array(); }\n"
}

// With "authorize":"0" there is no login: whoever opens the file can upload,
// edit and run files on the website. On 2026-09-30 an attacker with a stolen
// WordPress login had placed six copies on one website, each in a plugin
// folder with a made-up name. The rules then in place reported them as high,
// and the automatic quarantine left them alone.
func TestAFileManagerWithoutLoginIsCritical(t *testing.T) {
	e := NewEngine(nil)
	path := "/web/wp-content/plugins/nptrcmp/ooykfpdw.php"
	var found *report.Finding
	for _, f := range e.Scan(path, path, "php", []byte(fileManager("0"))) {
		if f.Rule == "php.tool.file_manager_open" {
			f := f
			found = &f
		}
	}
	if found == nil {
		t.Fatal("Dateimanager ohne Anmeldung nicht gemeldet")
	}
	if found.Severity != report.SeverityCritical {
		t.Errorf("Stufe %q, erwartet %q", found.Severity, report.SeverityCritical)
	}
	if r := ByID("php.tool.file_manager_open"); r == nil || !r.AutoSafe {
		t.Error("die Regel verschiebt nicht selbst in die Quarantäne")
	}
	if x, ok := Explain("php.tool.file_manager_open"); !ok || x.Why == "" || x.Advice == "" {
		t.Error("die Regel erklärt sich nicht")
	}
}

// With the login switched on it is a tool somebody may have meant to have,
// and a security plugin that names the tool in its signatures holds no such
// settings line in code.
func TestAFileManagerWithLoginOrANameIsNoOpenOne(t *testing.T) {
	e := NewEngine(nil)
	for _, c := range []struct{ name, src string }{
		{"mit Anmeldung", fileManager("1")},
		{"Signatur eines Sicherheits-Plugins", "<?php $sigs = array('PHP File man" + "ager ver', 'fm_" + "user');\n" +
			"// $authoriz" + "ation = '{\"author" + "ize\":\"0\"'\n"},
	} {
		if hitRules(e, "/web/wp-content/plugins/x/a.php", "php", c.src)["php.tool.file_manager_open"] {
			t.Errorf("%s: als offener Dateimanager gemeldet", c.name)
		}
	}
}
