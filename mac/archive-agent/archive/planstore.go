package archive

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const MaxPlanBytes = 512 << 20

type PlanStore struct {
	Path string
}

func (store PlanStore) Create(plan Plan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	content, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	content = append(content, '\n')
	if len(content) > MaxPlanBytes {
		return errors.New("archive plan exceeds 512 MiB")
	}
	directory, name, err := (StateStore{Path: store.Path}).openDirectory()
	if err != nil {
		return err
	}
	defer directory.Close()
	if _, err := statAtNoFollow(directory, name); err == nil {
		return errors.New("archive plan already exists")
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	return createPrivateFile(directory, name, content)
}

func (store PlanStore) Load() (Plan, error) {
	directory, name, err := (StateStore{Path: store.Path}).openDirectory()
	if err != nil {
		return Plan{}, err
	}
	defer directory.Close()
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return Plan{}, fmt.Errorf("open archive plan: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		unix.Close(fd)
		return Plan{}, errors.New("construct archive plan descriptor")
	}
	defer file.Close()
	if err := requirePrivateRegularFile(file); err != nil {
		return Plan{}, err
	}
	content, err := io.ReadAll(io.LimitReader(file, MaxPlanBytes+1))
	if err != nil {
		return Plan{}, err
	}
	if len(content) > MaxPlanBytes {
		return Plan{}, errors.New("archive plan exceeds 512 MiB")
	}
	var plan Plan
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, fmt.Errorf("decode archive plan: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Plan{}, err
	}
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func createPrivateFile(directory *os.File, name string, content []byte) error {
	random := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return err
	}
	temporary := "." + name + "." + hex.EncodeToString(random) + ".tmp"
	fd, err := unix.Openat(int(directory.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("create archive plan temporary file: %w", err)
	}
	temporaryExists := true
	defer func() {
		if temporaryExists {
			unix.Unlinkat(int(directory.Fd()), temporary, 0)
		}
	}()
	file := os.NewFile(uintptr(fd), temporary)
	if file == nil {
		unix.Close(fd)
		return errors.New("construct archive plan temporary descriptor")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Linkat(int(directory.Fd()), temporary, int(directory.Fd()), name, 0); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return errors.New("archive plan already exists")
		}
		return fmt.Errorf("publish immutable archive plan: %w", err)
	}
	if err := unix.Unlinkat(int(directory.Fd()), temporary, 0); err != nil {
		return fmt.Errorf("remove archive plan temporary link: %w", err)
	}
	temporaryExists = false
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync archive plan directory: %w", err)
	}
	return nil
}
