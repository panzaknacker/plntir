//go:build linux

package archive

import "golang.org/x/sys/unix"

func metadataFromStat(stat *unix.Stat_t) unixMetadata {
	mode := uint32(stat.Mode)
	return unixMetadata{
		identity: FileIdentity{
			Device:          uint64(stat.Dev),
			Inode:           stat.Ino,
			SizeBytes:       stat.Size,
			ModTimeUnixNano: stat.Mtim.Sec*1_000_000_000 + stat.Mtim.Nsec,
			Mode:            mode,
		},
		uid:      stat.Uid,
		gid:      stat.Gid,
		mode:     mode,
		typeBits: mode & unix.S_IFMT,
	}
}
