package rules

import (
	"testing"

	"github.com/brightcolor/malwatch/internal/report"
)

// severityOf returns the severity of rule's finding, or "" for none.
func severityOf(e *Engine, rule, content string) report.Severity {
	for _, f := range e.Scan("/web/wp-content/plugins/x/a.php", "/web/wp-content/plugins/x/a.php", "php", []byte(content)) {
		if f.Rule == rule {
			return f.Severity
		}
	}
	return ""
}

// Code that WordPress only runs for a user with the right capability and a
// valid nonce is a plugin's admin action, not a way in: whoever can reach it
// is an administrator already. LayerSlider saves its CSS editor that way,
// Easy Digital Downloads runs its exporters. Such a finding stays, one level
// lower, without a mail.
func TestGuardedAdminActionsAreLowered(t *testing.T) {
	e := NewEngine(nil)
	post := "$_PO" + "ST"
	req := "$_REQ" + "UEST"
	cases := []struct{ name, rule, src string }{
		{"Prüfung davor", "php.dynamic.request_call", "<?php function edd_do_export() {\n" +
			"  if ( ! current_user_can( 'export_shop_reports' ) ) { wp_die( 'no' ); }\n" +
			"  check_admin_referer( 'edd-export' );\n" +
			"  " + req + "['class']();\n}\n"},
		{"Anmeldung als Hook", "php.dropper.write_code", "<?php\nfunction ls_register_form_actions() {\n" +
			"  if (current_user_can('manage_options')) {\n" +
			"    if (isset(" + post + "['ls-user-css'])) {\n" +
			"      if (check_admin_referer('save-user-css')) { add_action('admin_init', 'ls_save_user_css'); }\n" +
			"    }\n  }\n}\n" +
			"function ls_save_user_css() {\n  file_put_contents($file, stripslashes(" + post + "['contents']));\n}\n"},
	}
	for _, c := range cases {
		if got := severityOf(e, c.rule, c.src); got != report.SeverityMedium {
			t.Errorf("%s: Stufe %q, erwartet %q", c.name, got, report.SeverityMedium)
		}
	}
}

func TestUnguardedActionsKeepTheirLevel(t *testing.T) {
	e := NewEngine(nil)
	post := "$_PO" + "ST"
	req := "$_REQ" + "UEST"
	cases := []struct {
		name, rule, src string
		want            report.Severity
	}{
		{"ohne Prüfung", "php.dynamic.request_call", "<?php " + req + "['class']();", report.SeverityCritical},
		{"nur Rechte", "php.dynamic.request_call", "<?php function f() { if (!current_user_can('x')) { return; } " + req + "['c'](); }", report.SeverityCritical},
		{"nur Nonce", "php.dynamic.request_call", "<?php function f() { check_admin_referer('x'); " + req + "['c'](); }", report.SeverityCritical},
		{"ein Hook ohne Prüfung", "php.dropper.write_code", "<?php\n" +
			"function reg() { if (current_user_can('x') && check_admin_referer('y')) { add_action('admin_init', 'save'); } }\n" +
			"add_action('init', 'save');\n" +
			"function save() { file_put_contents($f, " + post + "['c']); }\n", report.SeverityHigh},
		{"Prüfung in anderer Funktion", "php.dropper.write_code", "<?php\n" +
			"function check() { current_user_can('x'); check_admin_referer('y'); }\n" +
			"function save() { file_put_contents($f, " + post + "['c']); }\n", report.SeverityHigh},
	}
	for _, c := range cases {
		if got := severityOf(e, c.rule, c.src); got != c.want {
			t.Errorf("%s: Stufe %q, erwartet %q", c.name, got, c.want)
		}
	}
}
