package main

import (
	"flag"

	"github.com/brightcolor/malwatch/internal/diskspace"
	"github.com/brightcolor/malwatch/internal/quarantine"
)

// quarantineReserveFlag adds --quarantine-reserve to fs: the room, in MiB,
// every write of the quarantine leaves free. quarantine, repair and upgrade
// all write into the quarantine and take it the same way.
func quarantineReserveFlag(fs *flag.FlagSet) *int64 {
	return fs.Int64("quarantine-reserve", quarantine.DefaultReserveMiB, "")
}

// quarantineStat measures a filesystem for the space check of the
// quarantine; nil is the real measurement. Tests put their own in.
var quarantineStat func(path string) (diskspace.Usage, error)

// quarantineSpace turns --quarantine-reserve into the Space the quarantine
// measures with, or says why the value cannot serve.
func quarantineSpace(mib int64) (quarantine.Space, error) {
	if err := quarantine.CheckReserve(mib); err != nil {
		return quarantine.Space{}, err
	}
	return quarantine.Space{ReserveMiB: mib, Stat: quarantineStat}, nil
}
