#!/bin/sh
# Checks the wiring between the extension files that PHP cannot see.
#
# Every failure below has actually happened during the first install: the
# files are syntactically fine, so php -l passes, and the page only breaks
# when someone opens it.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
status=0

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	status=1
}

# 1. A page using tform_actions must set $tform_def_file. tform_actions reads
#    it from the global scope and dies without it.
for page in "$root"/interface/*.php; do
	# The word boundary matters: "listform_actions" contains "tform_actions",
	# and without it every list page would be reported as a broken form page.
	if grep -qE '(^|[^a-z])tform_actions' "$page" && ! grep -q '\$tform_def_file' "$page"; then
		fail "$(basename "$page") uses tform_actions but sets no \$tform_def_file"
	fi
done

# 2. The same for listform_actions and $list_def_file.
for page in "$root"/interface/*.php; do
	if grep -q 'listform_actions' "$page" && ! grep -q '\$list_def_file' "$page"; then
		fail "$(basename "$page") uses listform_actions but sets no \$list_def_file"
	fi
done

# 3. Every form and list definition named in a page must exist.
for page in "$root"/interface/*.php; do
	for def in $(grep -ohE "(form|list)/[a-z_]+\.(tform|list)\.php" "$page" || true); do
		[ -f "$root/interface/$def" ] || fail "$(basename "$page") references $def, which does not exist"
	done
done

# 4. A list definition implies a template and a language file whose names
#    ISPConfig derives from the list name, not from the file name.
for def in "$root"/interface/list/*.list.php; do
	[ -f "$def" ] || continue
	name=$(grep -oE "liste\['name'\][[:space:]]*=[[:space:]]*'[a-z_]+'" "$def" | head -1 | sed "s/.*'\([a-z_]*\)'/\1/")
	[ -n "$name" ] || { fail "$(basename "$def") has no liste['name']"; continue; }
	[ -f "$root/interface/templates/${name}_list.htm" ] || fail "template templates/${name}_list.htm for list $name is missing"
	for lang in de en; do
		[ -f "$root/interface/lang/${lang}_${name}_list.lng" ] || fail "language file ${lang}_${name}_list.lng for list $name is missing"
	done
done

# 5. The same for form definitions.
for def in "$root"/interface/form/*.tform.php; do
	[ -f "$def" ] || continue
	name=$(grep -oE "form\['name'\][[:space:]]*=[[:space:]]*'[a-z_]+'" "$def" | head -1 | sed "s/.*'\([a-z_]*\)'/\1/")
	[ -n "$name" ] || { fail "$(basename "$def") has no form['name']"; continue; }
	for lang in de en; do
		[ -f "$root/interface/lang/${lang}_${name}.lng" ] || fail "language file ${lang}_${name}.lng for form $name is missing"
	done
	for tpl in $(grep -ohE "templates/[a-z_]+\.htm" "$def" || true); do
		[ -f "$root/interface/$tpl" ] || fail "$(basename "$def") references $tpl, which does not exist"
	done
done

# 6. Every source named in file.list must exist, and every interface file must
#    be listed. A file that ships but is never installed is invisible; a line
#    pointing at nothing aborts enable_files halfway.
while IFS=: read -r action source target; do
	case "$action" in
		c|s|d) ;;
		*) continue ;;
	esac
	[ -e "$root/$source" ] || fail "file.list names $source, which does not exist"
done < "$root/install/file.list"

for file in $(cd "$root" && find interface server -type f | sort); do
	grep -q ":$file:" "$root/install/file.list" || fail "$file is not in install/file.list"
done

# 7. No native submit buttons. The panel binds [data-submit-form] and posts
#    by AJAX; a type="submit" button inside the panel produces no request at
#    all, so the button looks fine and simply does nothing.
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	if grep -q 'type="submit"' "$tpl"; then
		fail "$(basename "$tpl") uses type=\"submit\"; the panel needs type=\"button\" with data-submit-form"
	fi
done

# 8. A button that submits must name the form and the action, otherwise the
#    click is silently ignored.
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	subs=$(grep -c 'data-submit-form' "$tpl" || true)
	acts=$(grep -c 'data-form-action' "$tpl" || true)
	if [ "$subs" != "$acts" ]; then
		fail "$(basename "$tpl") has $subs data-submit-form but $acts data-form-action"
	fi
done

# 9. Templates must not reference a language key that neither language file
#    defines - the page would then show an empty label.
for tpl in "$root"/interface/templates/*.htm; do
	[ -f "$tpl" ] || continue
	for key in $(grep -ohE "tmpl_var name=['\"][a-z_]+_txt['\"]" "$tpl" | sed -E "s/.*['\"]([a-z_]+_txt)['\"]/\1/" | sort -u); do
		if ! grep -qhE "\\\$wb\['$key'\]" "$root"/interface/lang/de_*.lng; then
			fail "$(basename "$tpl") uses {$key}, which no German language file defines"
		fi
	done
done

if [ "$status" -eq 0 ]; then
	printf 'Wiring OK\n'
fi

exit "$status"
