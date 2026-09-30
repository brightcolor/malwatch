package phpcode

import "strings"

// OwnCode reports whether the eval or assert at offset at runs code its own
// function writes. That holds for a variable the function body assembles
// from quoted text that opens a function or class definition, joined with
// its parameters, its own variables and the results of functions that only
// format (formatters): XML-RPC and mock libraries write their wrappers this
// way. Anything read from the request, a file or the network, anything
// decoded and anything returned by a call through a variable makes the code
// foreign, and so does every eval at the top level of a file, of a parameter
// or of a variable the function cannot vouch for.
func (s *Source) OwnCode(at int) bool {
	e := s.tokenAt(at)
	if e < 0 || s.toks[e].kind != tIdent || (s.toks[e].val != "eval" && s.toks[e].val != "assert") {
		return false
	}
	name, ok := s.evaluated(e)
	if !ok {
		return false
	}
	k := s.scopeIndex(s.toks[e].pos)
	if k < 0 {
		return false
	}
	b, ok := s.body(k)
	if !ok {
		return false
	}
	return b.writes(name, s.toks[e].pos)
}

// tokenAt returns the index of the token that starts at offset at, or -1.
func (s *Source) tokenAt(at int) int {
	lo, hi := 0, len(s.toks)
	for lo < hi {
		m := (lo + hi) / 2
		if s.toks[m].pos < at {
			lo = m + 1
		} else {
			hi = m
		}
	}
	if lo < len(s.toks) && s.toks[lo].pos == at {
		return lo
	}
	return -1
}

// evaluated returns the variable an eval or assert at token e gets as its
// whole argument, optionally behind @.
func (s *Source) evaluated(e int) (string, bool) {
	j := e + 1
	if j >= len(s.toks) || !isPunct(s.toks[j], "(") {
		return "", false
	}
	j++
	if j < len(s.toks) && isPunct(s.toks[j], "@") {
		j++
	}
	if j+1 >= len(s.toks) || s.toks[j].kind != tVar || !isPunct(s.toks[j+1], ")") {
		return "", false
	}
	return s.toks[j].val, true
}

// funcBody is the code of one function: its tokens without those of the
// functions and closures defined inside it, and the names it gets from
// outside - its parameters and the variables of a closure's use list.
type funcBody struct {
	toks    []token
	outside map[string]bool
}

// body collects the function body of scope k.
func (s *Source) body(k int) (*funcBody, bool) {
	sc := s.scopes[k]
	open := s.tokenAt(sc.Start)
	if open < 0 {
		return nil, false
	}
	b := &funcBody{outside: map[string]bool{}}
	head := open - 1
	for head >= 0 && !(s.toks[head].kind == tIdent && (s.toks[head].val == "function" || s.toks[head].val == "fn")) {
		if s.toks[head].kind == tVar {
			b.outside[s.toks[head].val] = true
		}
		head--
	}
	if head < 0 {
		return nil, false
	}
	var inner []Scope
	for j, other := range s.scopes {
		if j != k && other.Start > sc.Start && other.End < sc.End {
			inner = append(inner, other)
		}
	}
	for i := open + 1; i < len(s.toks) && s.toks[i].pos < sc.End; i++ {
		pos := s.toks[i].pos
		nested := false
		for _, o := range inner {
			if o.Start <= pos && pos <= o.End {
				nested = true
				break
			}
		}
		if !nested {
			b.toks = append(b.toks, s.toks[i])
		}
	}
	return b, true
}

// definitionWords open the definition of a function or class, the only
// code OwnCode lets a function write for itself.
var definitionWords = []string{"function", "class", "abstract", "final", "interface", "trait", "enum", "readonly"}

// formatters only turn values into text; a call to one of them adds nothing
// that was not in its arguments.
var formatters = map[string]bool{
	"implode": true, "join": true, "count": true, "sizeof": true, "var_export": true, "str_repeat": true,
	"strtolower": true, "strtoupper": true, "ucfirst": true, "lcfirst": true, "ucwords": true, "trim": true,
	"ltrim": true, "rtrim": true, "str_replace": true, "sprintf": true, "intval": true, "strval": true,
	"floatval": true, "addslashes": true, "addcslashes": true, "json_encode": true, "serialize": true,
	"str_pad": true, "strlen": true, "preg_quote": true, "number_format": true, "dechex": true,
}

// foreignSources are the PHP functions whose result comes from outside the
// code or out of a decoder: the request and the environment, files, the
// network, decoding and decryption, and calls to a function named at run
// time.
var foreignSources = map[string]bool{
	"getenv": true, "apache_request_headers": true, "getallheaders": true, "filter_input": true,
	"filter_input_array": true, "file_get_contents": true, "file": true, "fread": true, "fgets": true,
	"fgetc": true, "fgetss": true, "fscanf": true, "stream_get_contents": true, "stream_socket_recvfrom": true,
	"gzfile": true, "gzread": true, "gzgets": true, "bzread": true, "readfile": true, "fpassthru": true,
	"simplexml_load_file": true, "parse_ini_file": true, "curl_exec": true, "curl_multi_getcontent": true,
	"fsockopen": true, "pfsockopen": true, "socket_read": true, "socket_recv": true, "socket_recvfrom": true,
	"stream_socket_client": true, "get_headers": true, "base64_decode": true, "convert_uudecode": true,
	"gzinflate": true, "gzuncompress": true, "gzdecode": true, "zlib_decode": true, "bzdecompress": true,
	"lzf_decompress": true, "str_rot13": true, "hex2bin": true, "pack": true, "unpack": true,
	"urldecode": true, "rawurldecode": true, "html_entity_decode": true, "htmlspecialchars_decode": true,
	"quoted_printable_decode": true, "strrev": true, "strtr": true, "chr": true, "unserialize": true,
	"openssl_decrypt": true, "openssl_private_decrypt": true, "openssl_public_decrypt": true,
	"mcrypt_decrypt": true, "mdecrypt_generic": true, "sodium_crypto_secretbox_open": true,
	"sodium_crypto_box_open": true, "call_user_func": true, "call_user_func_array": true,
	"create_function": true, "func_get_args": true, "func_get_arg": true, "get_defined_vars": true,
	"session_decode": true,
}

// requestVars are the variables PHP fills from the request and the
// environment.
var requestVars = map[string]bool{
	"$_GET": true, "$_POST": true, "$_REQUEST": true, "$_COOKIE": true, "$_SERVER": true, "$_FILES": true,
	"$_ENV": true, "$_SESSION": true, "$HTTP_RAW_POST_DATA": true, "$HTTP_GET_VARS": true,
	"$HTTP_POST_VARS": true, "$HTTP_COOKIE_VARS": true, "$HTTP_SERVER_VARS": true, "$argv": true,
}

// refWriters are PHP functions that write into variables they are handed,
// or define variables by name.
var refWriters = map[string]bool{
	"preg_match": true, "preg_match_all": true, "parse_str": true, "mb_parse_str": true, "extract": true,
	"exec": true, "system": true, "passthru": true, "sscanf": true, "settype": true, "openssl_open": true,
	"openssl_seal": true, "openssl_private_decrypt": true, "openssl_public_decrypt": true, "similar_text": true,
	"import_request_variables": true,
}

// assignment is one place where the body gives variables a value.
type assignment struct {
	targets []string
	op      string
	rhs     []token
	pos     int
}

// writes reports whether the body writes the variable name itself, as
// OwnCode describes, before the eval at offset at.
func (b *funcBody) writes(name string, at int) bool {
	if b.outside[name] || !b.plain(name) {
		return false
	}
	assigns := b.assignments()
	tainted := b.tainted(assigns)
	var own []assignment
	for _, a := range assigns {
		for _, t := range a.targets {
			if t == name {
				own = append(own, a)
			}
		}
	}
	if len(own) == 0 || own[0].pos > at || own[0].op != "=" || len(own[0].rhs) == 0 ||
		!opensDefinition(own[0].rhs[0]) {
		return false
	}
	for _, a := range own {
		if len(a.targets) != 1 || (a.op != "=" && a.op != ".=") || !b.template(a.rhs, tainted) {
			return false
		}
	}
	return true
}

// plain reports whether the body only ever reads name or assigns it as a
// whole: no reference to it, no global or static declaration, no element or
// property written, no loop, catch or parameter list that fills it, no call
// that may write into it, and no construct that sets variables by name.
func (b *funcBody) plain(name string) bool {
	toks := b.toks
	var parens []int
	for i, t := range toks {
		switch {
		case isPunct(t, "$"):
			return false
		case t.kind == tIdent && (t.val == "extract" || t.val == "parse_str" || t.val == "mb_parse_str" ||
			t.val == "import_request_variables"):
			return false
		case t.kind == tIdent && (t.val == "global" || t.val == "static") && i+1 < len(toks) && toks[i+1].kind == tVar:
			for j := i + 1; j < len(toks) && !isPunct(toks[j], ";"); j++ {
				if toks[j].kind == tVar && toks[j].val == name {
					return false
				}
			}
		case t.kind == tIdent && (t.val == "function" || t.val == "fn" || t.val == "catch"):
			if j := indexOf(toks, i+1, "("); j >= 0 {
				if end := closing(toks, j); end > j {
					for _, u := range toks[j:end] {
						if u.kind == tVar && u.val == name {
							return false
						}
					}
				}
			}
		case isPunct(t, "("):
			parens = append(parens, i)
		case isPunct(t, ")"):
			if len(parens) > 0 {
				parens = parens[:len(parens)-1]
			}
		}
		if t.kind != tVar || t.val != name {
			continue
		}
		if i > 0 && (isPunct(toks[i-1], "&") || isIdent(toks[i-1], "as") || isPunct(toks[i-1], "=>")) {
			return false
		}
		if len(parens) > 0 && !b.readingCall(parens[len(parens)-1]) {
			return false
		}
		next := i + 1
		for next < len(toks) && isPunct(toks[next], "[") {
			end := closing(toks, next)
			if end < 0 {
				return false
			}
			next = end + 1
			if next >= len(toks) || assigns(toks, next) {
				return false
			}
		}
		if next < len(toks) && (isPunct(toks[next], "->") || isPunct(toks[next], "::")) {
			return false
		}
		if next < len(toks) && (isPunct(toks[next], ")") || isPunct(toks[next], "]") || isPunct(toks[next], ",")) &&
			partOfTarget(toks, next) {
			return false
		}
		if next < len(toks) && compound(toks, next) {
			return false
		}
	}
	return true
}

// readingCall reports whether the parenthesis at open belongs to something
// that only reads its arguments: a control structure or language construct,
// eval, assert or a formatter.
func (b *funcBody) readingCall(open int) bool {
	if open == 0 {
		return true
	}
	prev := b.toks[open-1]
	if prev.kind == tIdent {
		if open >= 2 && (isPunct(b.toks[open-2], "->") || isPunct(b.toks[open-2], "::")) {
			return false
		}
		return notCalls[prev.val] || formatters[prev.val] || prev.val == "eval" || prev.val == "assert"
	}
	return prev.kind == tPunct && prev.val != ")" && prev.val != "]"
}

// assigns reports whether the token at i gives what stands before it a
// value.
func assigns(toks []token, i int) bool {
	return isPunct(toks[i], "=") || isPunct(toks[i], ".=") || compound(toks, i)
}

// compound reports whether an assignment that combines the old value with a
// new one starts at token i: +=, -=, *=, /=, %=, ^=, |=, &=, <<=, >>=, ??=
// and **=.
func compound(toks []token, i int) bool {
	at := func(k int, v string) bool { return k < len(toks) && isPunct(toks[k], v) }
	switch {
	case at(i, "+="), at(i, "-="):
		return true
	case at(i, "^"), at(i, "|"), at(i, "&"), at(i, "/"), at(i, "%"), at(i, "??"):
		return at(i+1, "=")
	case at(i, "*"):
		return at(i+1, "=") || (at(i+1, "*") && at(i+2, "="))
	case at(i, "<"):
		return at(i+1, "<=")
	case at(i, ">"):
		return at(i+1, ">=")
	}
	return false
}

// partOfTarget reports whether the closing token at i ends the left side of
// an assignment - a list() or [...] that is filled, or an element written -
// so that a variable inside it is written, not read.
func partOfTarget(toks []token, i int) bool {
	for j := i; j < len(toks); j++ {
		t := toks[j]
		if isPunct(t, ",") || t.kind == tVar || t.kind == tStr || t.kind == tNum {
			continue
		}
		if isPunct(t, ")") || isPunct(t, "]") {
			if j+1 < len(toks) && assigns(toks, j+1) {
				return true
			}
			continue
		}
		return false
	}
	return false
}

// indexOf returns the index of the first punctuation v at or after from, or
// -1.
func indexOf(toks []token, from int, v string) int {
	for j := from; j < len(toks); j++ {
		if isPunct(toks[j], v) {
			return j
		}
	}
	return -1
}

// closing returns the index of the token that closes the bracket at open, or
// -1.
func closing(toks []token, open int) int {
	depth := 0
	for j := open; j < len(toks); j++ {
		switch {
		case isPunct(toks[j], "("), isPunct(toks[j], "["), isPunct(toks[j], "{"):
			depth++
		case isPunct(toks[j], ")"), isPunct(toks[j], "]"), isPunct(toks[j], "}"):
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

// rhsEnd returns the index where the value that starts at token from ends:
// at a semicolon or comma of its own level, at the bracket that closes the
// group it stands in, or at a closing tag.
func rhsEnd(toks []token, from int) int {
	depth := 0
	for j := from; j < len(toks); j++ {
		t := toks[j]
		switch {
		case t.kind == tEnd:
			return j
		case isPunct(t, "("), isPunct(t, "["), isPunct(t, "{"):
			depth++
		case isPunct(t, ")"), isPunct(t, "]"), isPunct(t, "}"):
			if depth == 0 {
				return j
			}
			depth--
		case depth == 0 && (isPunct(t, ";") || isPunct(t, ",")):
			return j
		}
	}
	return len(toks)
}

// assignments lists where the body gives variables a value: plain and
// combining assignments, elements and properties written, list() and [...]
// filled, the variables of a foreach, those handed to a function that writes
// into them and those declared global.
func (b *funcBody) assignments() []assignment {
	toks := b.toks
	var out []assignment
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case isPunct(t, "=") || isPunct(t, ".=") || compound(toks, i):
			op, from := "compound", i+1
			switch {
			case isPunct(t, "=") || isPunct(t, ".="):
				op = t.val
			default:
				for from < len(toks) && !isPunct(toks[from-1], "=") && !isPunct(toks[from-1], "+=") &&
					!isPunct(toks[from-1], "-=") && !isPunct(toks[from-1], "<=") && !isPunct(toks[from-1], ">=") {
					from++
				}
			}
			start := target(toks, i)
			if start < 0 {
				i = from - 1
				continue
			}
			var targets []string
			for _, u := range toks[start:i] {
				if u.kind == tVar {
					targets = append(targets, u.val)
				}
			}
			if start != i-1 && op != "compound" {
				op = "element"
			}
			end := rhsEnd(toks, from)
			out = append(out, assignment{targets: targets, op: op, rhs: toks[from:end], pos: toks[start].pos})
			i = from - 1
		case isIdent(t, "foreach") && i+1 < len(toks) && isPunct(toks[i+1], "("):
			end := closing(toks, i+1)
			if end < 0 {
				continue
			}
			as := -1
			for j := i + 2; j < end; j++ {
				if isIdent(toks[j], "as") {
					as = j
					break
				}
			}
			if as < 0 {
				continue
			}
			var targets []string
			for _, u := range toks[as+1 : end] {
				if u.kind == tVar {
					targets = append(targets, u.val)
				}
			}
			out = append(out, assignment{targets: targets, op: "foreach", rhs: toks[i+2 : as], pos: t.pos})
		case t.kind == tIdent && refWriters[t.val] && i+1 < len(toks) && isPunct(toks[i+1], "("):
			end := closing(toks, i+1)
			if end < 0 {
				continue
			}
			var targets []string
			for _, u := range toks[i+2 : end] {
				if u.kind == tVar {
					targets = append(targets, u.val)
				}
			}
			out = append(out, assignment{targets: targets, op: "call", rhs: toks[i+2 : end], pos: t.pos})
		case (isIdent(t, "global") || isIdent(t, "static")) && i+1 < len(toks) && toks[i+1].kind == tVar:
			var targets []string
			for j := i + 1; j < len(toks) && !isPunct(toks[j], ";"); j++ {
				if toks[j].kind == tVar {
					targets = append(targets, toks[j].val)
				}
			}
			// A global comes from wherever the rest of the program set it.
			if isIdent(t, "global") {
				out = append(out, assignment{targets: targets, op: "global", pos: t.pos})
			}
		}
	}
	return out
}

// target returns the index where the left side of the assignment operator at
// op starts: a variable with the elements and properties written into it, or
// a list() or [...] that is filled. -1 means no variable gets the value.
func target(toks []token, op int) int {
	j := op - 1
	for j >= 0 {
		t := toks[j]
		switch {
		case isPunct(t, "]"):
			open := opening(toks, j)
			if open < 0 {
				return -1
			}
			if open == 0 || !(toks[open-1].kind == tVar || toks[open-1].kind == tIdent || isPunct(toks[open-1], "]")) {
				return open
			}
			j = open - 1
			continue
		case isPunct(t, ")"):
			if open := opening(toks, j); open > 0 && isIdent(toks[open-1], "list") {
				return open - 1
			}
			return -1
		case t.kind == tIdent && j > 0 && isPunct(toks[j-1], "->"):
			j -= 2
			continue
		case t.kind == tVar && j > 0 && isPunct(toks[j-1], "->"):
			j -= 2
			continue
		case t.kind == tVar:
			return j
		}
		return -1
	}
	return -1
}

// opening returns the index of the bracket that the one at close closes, or
// -1.
func opening(toks []token, close int) int {
	depth := 0
	for j := close; j >= 0; j-- {
		switch {
		case isPunct(toks[j], ")"), isPunct(toks[j], "]"), isPunct(toks[j], "}"):
			depth++
		case isPunct(toks[j], "("), isPunct(toks[j], "["), isPunct(toks[j], "{"):
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return -1
}

// tainted returns the variables of the body that can carry foreign data:
// those assigned from the request, a file, the network, a decoder, a call
// through a variable or a global, and those assigned from one of them, as
// often as it takes.
func (b *funcBody) tainted(assigns []assignment) map[string]bool {
	out := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for _, a := range assigns {
			if !(a.op == "global" || foreignValue(a.rhs, out)) {
				continue
			}
			for _, t := range a.targets {
				if !out[t] {
					out[t] = true
					changed = true
				}
			}
		}
	}
	return out
}

// foreignValue reports whether a value reads anything foreign: a variable of
// the request, a request variable through $GLOBALS, a shell command, an
// include, a foreign source, a call through a variable, the bit operators a
// decoder uses, or a variable already tainted.
func foreignValue(toks []token, tainted map[string]bool) bool {
	for i, t := range toks {
		switch t.kind {
		case tVar:
			if requestVars[t.val] || tainted[t.val] || (t.val == "$GLOBALS" && !plainGlobal(toks, i)) {
				return true
			}
			if calledThrough(toks, i) {
				return true
			}
		case tStrDyn:
			if !cleanText(t.val, tainted) {
				return true
			}
		case tShell:
			return true
		case tIdent:
			if t.val == "include" || t.val == "include_once" || t.val == "require" || t.val == "require_once" {
				return true
			}
			if foreignSources[t.val] && i+1 < len(toks) && isPunct(toks[i+1], "(") {
				return true
			}
		case tPunct:
			if t.val == "^" || t.val == "~" {
				return true
			}
		}
	}
	return false
}

// plainGlobal reports whether $GLOBALS at token i names a setting of the
// program: a quoted key that does not start with an underscore, as the
// request variables do.
func plainGlobal(toks []token, i int) bool {
	return i+3 < len(toks) && isPunct(toks[i+1], "[") && toks[i+2].kind == tStr &&
		!strings.HasPrefix(toks[i+2].val, "_") && isPunct(toks[i+3], "]")
}

// calledThrough reports whether the variable at token i is called: $f(),
// $a['f']() or $o->$m().
func calledThrough(toks []token, i int) bool {
	j := i + 1
	for j < len(toks) {
		switch {
		case isPunct(toks[j], "["):
			end := closing(toks, j)
			if end < 0 {
				return true
			}
			j = end + 1
			continue
		case isPunct(toks[j], "->") && j+1 < len(toks) && toks[j+1].kind == tIdent:
			if j+2 < len(toks) && isPunct(toks[j+2], "(") {
				return false
			}
			j += 2
			continue
		case isPunct(toks[j], "->") && j+1 < len(toks) && toks[j+1].kind == tVar:
			return true
		}
		break
	}
	return j < len(toks) && isPunct(toks[j], "(")
}

// template reports whether toks is text the body writes: quoted strings,
// numbers, constants and untainted variables joined with the dot, with
// calls to formatters around them.
func (b *funcBody) template(toks []token, tainted map[string]bool) bool {
	if len(toks) == 0 {
		return false
	}
	j := 0
	for {
		next, ok := b.operand(toks, j, tainted)
		if !ok {
			return false
		}
		if next == len(toks) {
			return true
		}
		if !isPunct(toks[next], ".") {
			return false
		}
		j = next + 1
		if j >= len(toks) {
			return false
		}
	}
}

// operand reads one part of a template at token j and returns the index
// behind it.
func (b *funcBody) operand(toks []token, j int, tainted map[string]bool) (int, bool) {
	t := toks[j]
	switch t.kind {
	case tStr, tNum:
		return j + 1, true
	case tStrDyn:
		return j + 1, cleanText(t.val, tainted)
	case tPunct:
		if t.val != "(" {
			return 0, false
		}
		end := closing(toks, j)
		if end < 0 || !b.template(toks[j+1:end], tainted) {
			return 0, false
		}
		return end + 1, true
	case tVar:
		if requestVars[t.val] || tainted[t.val] {
			return 0, false
		}
		if t.val == "$GLOBALS" && !plainGlobal(toks, j) {
			return 0, false
		}
		j++
		for j < len(toks) {
			switch {
			case isPunct(toks[j], "["):
				end := closing(toks, j)
				if end < 0 || (end > j+1 && !b.template(toks[j+1:end], tainted)) {
					return 0, false
				}
				j = end + 1
				continue
			case isPunct(toks[j], "->"):
				if j+1 >= len(toks) || toks[j+1].kind != tIdent || (j+2 < len(toks) && isPunct(toks[j+2], "(")) {
					return 0, false
				}
				j += 2
				continue
			case isPunct(toks[j], "("), isPunct(toks[j], "::"):
				return 0, false
			}
			break
		}
		return j, true
	case tIdent:
		if j+1 < len(toks) && isPunct(toks[j+1], "(") {
			if !formatters[t.val] {
				return 0, false
			}
			end := closing(toks, j+1)
			if end < 0 {
				return 0, false
			}
			from := j + 2
			for from < end {
				argEnd := rhsEnd(toks[:end], from)
				if argEnd == from || !b.template(toks[from:argEnd], tainted) {
					return 0, false
				}
				from = argEnd + 1
			}
			return end + 1, true
		}
		if j+1 < len(toks) && isPunct(toks[j+1], "::") {
			if j+2 < len(toks) && toks[j+2].kind == tIdent && !(j+3 < len(toks) && isPunct(toks[j+3], "(")) {
				return j + 3, true
			}
			return 0, false
		}
		if notCalls[t.val] || t.val == "clone" || t.val == "static" || t.val == "self" || t.val == "parent" ||
			t.val == "exit" || t.val == "die" || t.val == "yield" || t.val == "throw" || t.val == "eval" {
			return 0, false
		}
		return j + 1, true
	}
	return 0, false
}

// cleanText reports whether PHP fills nothing foreign into the body of a
// double quoted string or heredoc: no request variable, no request variable
// through $GLOBALS, no tainted variable, no call and no ${...}.
func cleanText(body string, tainted map[string]bool) bool {
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\\':
			i++
		case '$':
			if i+1 < len(body) && body[i+1] == '{' {
				return false
			}
			if i+1 >= len(body) || !isIdentStart(body[i+1]) {
				continue
			}
			j := i + 1
			for j < len(body) && isIdentByte(body[j]) {
				j++
			}
			name := body[i:j]
			if requestVars[name] || tainted[name] {
				return false
			}
			if name == "$GLOBALS" && (j >= len(body) || body[j] != '[' || strings.HasPrefix(strings.TrimLeft(body[j+1:], "'\""), "_")) {
				return false
			}
			i = j - 1
		case '{':
			if i+1 >= len(body) || body[i+1] != '$' {
				continue
			}
			end := braceEnd([]byte(body), i)
			if end < 0 {
				return false
			}
			inner := body[i+1 : end]
			if strings.ContainsAny(inner, "(`") {
				return false
			}
			if !cleanText(inner, tainted) {
				return false
			}
			i = end
		}
	}
	return true
}

// opensDefinition reports whether a quoted string starts the definition of
// a function or class, after white space, escaped line breaks and an open
// tag.
func opensDefinition(t token) bool {
	if t.kind != tStr && t.kind != tStrDyn {
		return false
	}
	s := t.val
	for {
		trimmed := strings.TrimLeft(s, " \t\r\n")
		for _, esc := range []string{`\n`, `\r`, `\t`} {
			trimmed = strings.TrimPrefix(trimmed, esc)
		}
		if trimmed == s {
			break
		}
		s = trimmed
	}
	if len(s) >= 5 && strings.EqualFold(s[:5], "<?php") {
		s = strings.TrimLeft(s[5:], " \t\r\n")
	}
	lower := strings.ToLower(s)
	for _, w := range definitionWords {
		if strings.HasPrefix(lower, w) && (len(lower) == len(w) || !isIdentByte(lower[len(w)])) {
			return true
		}
	}
	return false
}
