#!/bin/sh
# Checks the GitHub workflows: every workflow names the rights of its token in
# a permissions block at the top level, and every action is pinned to a full
# commit SHA. A local action (./) and a container image (docker://) are taken
# as they are.
#
#   sh tools/check-workflows.sh [FOLDER]     (default: .github/workflows)
set -eu

dir=${1:-.github/workflows}
if [ ! -d "$dir" ]; then
	echo "check-workflows.sh: $dir is not a folder. Run the check from the root of the repository or name the folder of the workflows." >&2
	exit 2
fi

status=0
found=0
for file in "$dir"/*.yml "$dir"/*.yaml; do
	[ -f "$file" ] || continue
	found=$((found + 1))

	if ! grep -q '^permissions:' "$file"; then
		echo "$file: no permissions block at the top level. Add one with the rights the jobs need, for instance:" >&2
		echo "  permissions:" >&2
		echo "    contents: read" >&2
		status=1
	fi

	refs=$(grep -nE '^[[:space:]]*(-[[:space:]]+)?uses:' "$file" || true)
	loose=$(printf '%s\n' "$refs" \
		| grep -vE 'uses:[[:space:]]+(\./|docker://)' \
		| grep -vE 'uses:[[:space:]]+[^@[:space:]]+@[0-9a-f]{40}([[:space:]]|$)' || true)
	if [ -n "$loose" ]; then
		printf '%s\n' "$loose" | while IFS= read -r line; do
			echo "$file:$line" >&2
		done
		echo "$file: the actions above are not pinned to a commit. Pin each to the full SHA of its release and keep the version as a comment, for instance:" >&2
		echo "  uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0" >&2
		status=1
	fi
done

if [ "$found" -eq 0 ]; then
	echo "check-workflows.sh: $dir holds no workflow (.yml or .yaml). Name the folder of the workflows." >&2
	exit 2
fi
if [ "$status" -eq 0 ]; then
	echo "$found workflow(s): permissions set, every action pinned to a commit"
fi
exit "$status"
