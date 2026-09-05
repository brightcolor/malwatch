// Command malwatch scans web space for malware and outdated web software.
package main

import (
	"fmt"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stdout)
		return 0
	}

	switch args[0] {
	case "scan":
		return cmdScan(args[1:])
	case "repair":
		return cmdRepair(args[1:])
	case "quarantine":
		return cmdQuarantine(args[1:])
	case "update":
		return cmdUpdate(args[1:])
	case "whitelist":
		return cmdWhitelist(args[1:])
	case "version", "--version", "-v":
		return cmdVersion()
	case "help", "--help", "-h":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unbekannter Befehl %q.\n\n", args[0])
		usage(os.Stderr)
		return 3
	}
}
