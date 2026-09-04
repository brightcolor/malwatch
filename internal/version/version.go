// Package version holds the build version of malwatch.
package version

// Version is the semantic version. Overridden at build time via ldflags.
var Version = "0.2.2"

// SchemaVersion is the version of the JSON report format. Consumers (the
// ISPConfig addon) check this before parsing a report.
const SchemaVersion = 1
