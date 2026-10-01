//go:build darwin || linux

package archive

import (
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

type unixMetadata struct {
	identity FileIdentity
	uid      uint32
	gid      uint32
	mode     uint32
	typeBits uint32
}

func openRootNoFollow(root string) (*os.File, error) {
	if !path.IsAbs(root) || path.Clean(root) != root {
		return nil, errors.New("archive root must be a clean absolute path")
	}
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_DIRECTORY | unix.O_NOFOLLOW
	fd, err := unix.Open("/", flags, 0)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	current := os.NewFile(uintptr(fd), "/")
	if current == nil {
		unix.Close(fd)
		return nil, errors.New("construct filesystem root descriptor")
	}
	if root == "/" {
		return current, nil
	}
	for _, component := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			current.Close()
			return nil, errors.New("archive root contains an unsafe component")
		}
		nextFD, openErr := unix.Openat(int(current.Fd()), component, flags, 0)
		current.Close()
		if openErr != nil {
			return nil, fmt.Errorf("open archive root component %q without symlinks: %w", component, openErr)
		}
		current = os.NewFile(uintptr(nextFD), component)
		if current == nil {
			unix.Close(nextFD)
			return nil, errors.New("construct archive root component descriptor")
		}
	}
	return current, nil
}

func directoryNames(directory *os.File) ([]string, error) {
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func statAtNoFollow(directory *os.File, name string) (unixMetadata, error) {
	if !safeBaseName(name) {
		return unixMetadata{}, errors.New("unsafe directory entry name")
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return unixMetadata{}, err
	}
	return metadataFromStat(&stat), nil
}

func statFile(file *os.File) (unixMetadata, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return unixMetadata{}, err
	}
	return metadataFromStat(&stat), nil
}

func openDirectoryAt(directory *os.File, name string) (*os.File, error) {
	if !safeBaseName(name) {
		return nil, errors.New("unsafe directory entry name")
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("construct directory descriptor")
	}
	return file, nil
}

func readLinkAt(directory *os.File, name string) (string, error) {
	if !safeBaseName(name) {
		return "", errors.New("unsafe directory entry name")
	}
	buffer := make([]byte, 256)
	for len(buffer) <= 1<<20 {
		count, err := unix.Readlinkat(int(directory.Fd()), name, buffer)
		if err != nil {
			return "", err
		}
		if count < len(buffer) {
			return string(buffer[:count]), nil
		}
		buffer = make([]byte, len(buffer)*2)
	}
	return "", errors.New("symlink target exceeds 1 MiB")
}

func openRegularNoFollow(root, relative string) (*os.File, FileIdentity, error) {
	if err := validateRelativePath(relative); err != nil {
		return nil, FileIdentity{}, err
	}
	directory, err := openRootNoFollow(root)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	components := strings.Split(relative, "/")
	for _, component := range components[:len(components)-1] {
		next, openErr := openDirectoryAt(directory, component)
		directory.Close()
		if openErr != nil {
			return nil, FileIdentity{}, fmt.Errorf("open archive path component %q: %w", component, openErr)
		}
		directory = next
	}
	name := components[len(components)-1]
	fd, openErr := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	directory.Close()
	if openErr != nil {
		return nil, FileIdentity{}, fmt.Errorf("open archive file %q without symlinks: %w", relative, openErr)
	}
	file := os.NewFile(uintptr(fd), relative)
	if file == nil {
		unix.Close(fd)
		return nil, FileIdentity{}, errors.New("construct archive file descriptor")
	}
	metadata, statErr := statFile(file)
	if statErr != nil {
		file.Close()
		return nil, FileIdentity{}, statErr
	}
	if metadata.typeBits != unix.S_IFREG {
		file.Close()
		return nil, FileIdentity{}, fmt.Errorf("archive path %q is no longer a regular file", relative)
	}
	return file, metadata.identity, nil
}

func safeBaseName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.Contains(name, "/") && !strings.ContainsRune(name, '\x00')
}
