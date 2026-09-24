#!/bin/sh
# Refuses release binaries that are not statically linked. Built with cgo, the
# binary links against the glibc of the build host and will not start on older
# systems (Ubuntu 20.04: "version `GLIBC_2.34' not found").
#
#   sh tools/check-static.sh dist/malwatch-linux-amd64 dist/malwatch-linux-arm64
set -eu

if [ "$#" -eq 0 ]; then
	echo "Usage: sh tools/check-static.sh BINARY..." >&2
	exit 2
fi
if ! command -v file >/dev/null 2>&1; then
	echo "check-static.sh needs the command file to inspect the binaries. Install it (apt-get install file) and run the check again." >&2
	exit 2
fi

status=0
for bin in "$@"; do
	if [ ! -f "$bin" ]; then
		echo "$bin is missing: the build did not produce it." >&2
		status=1
		continue
	fi
	info=$(file -bL "$bin")
	case "$info" in
	*"statically linked"*)
		echo "$bin: statically linked"
		;;
	*"dynamically linked"*)
		echo "$bin is dynamically linked and will not start on systems with an older glibc, such as Ubuntu 20.04." >&2
		echo "  file: $info" >&2
		echo "  Build it with CGO_ENABLED=0; make dist does that." >&2
		status=1
		;;
	*)
		echo "$bin is not a statically linked Linux binary." >&2
		echo "  file: $info" >&2
		echo "  Build it for Linux with CGO_ENABLED=0; make dist does that." >&2
		status=1
		;;
	esac
done

exit "$status"
