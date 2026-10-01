package lambdapack

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const maximumBinaryBytes = 200 << 20

var fixedZIPTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

func Pack(inputPath, outputPath string) error {
	inputPath = filepath.Clean(inputPath)
	outputPath = filepath.Clean(outputPath)
	inputAbs, err := filepath.Abs(inputPath)
	if err != nil {
		return err
	}
	outputAbs, err := filepath.Abs(outputPath)
	if err != nil {
		return err
	}
	if inputAbs == outputAbs {
		return errors.New("Lambda input and output paths must differ")
	}
	inputInfo, err := os.Lstat(inputAbs)
	if err != nil {
		return fmt.Errorf("stat Lambda binary: %w", err)
	}
	if !inputInfo.Mode().IsRegular() || inputInfo.Mode()&os.ModeSymlink != 0 || inputInfo.Mode().Perm()&0o111 == 0 ||
		inputInfo.Size() <= 0 || inputInfo.Size() > maximumBinaryBytes {
		return errors.New("Lambda binary must be a bounded executable regular non-symlink file")
	}
	input, err := os.Open(inputAbs)
	if err != nil {
		return err
	}
	defer input.Close()
	openedInfo, err := input.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(inputInfo, openedInfo) {
		return errors.New("Lambda binary changed while it was opened")
	}
	parent := filepath.Dir(outputAbs)
	if info, err := os.Lstat(parent); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Lambda output directory must be an existing non-symlink directory")
	}
	temporary, err := os.CreateTemp(parent, ".plntir-lambda-*.zip")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	succeeded := false
	defer func() {
		_ = temporary.Close()
		if !succeeded {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	archive := zip.NewWriter(temporary)
	header := &zip.FileHeader{Name: "bootstrap", Method: zip.Store}
	header.SetMode(0o755)
	header.SetModTime(fixedZIPTime)
	entry, err := archive.CreateHeader(header)
	if err != nil {
		return err
	}
	copied, err := io.Copy(entry, io.LimitReader(input, maximumBinaryBytes+1))
	if err != nil {
		return err
	}
	finalInfo, err := input.Stat()
	if err != nil || copied != inputInfo.Size() || finalInfo.Size() != inputInfo.Size() ||
		!finalInfo.ModTime().Equal(inputInfo.ModTime()) || !os.SameFile(inputInfo, finalInfo) {
		return errors.New("Lambda binary changed while it was packaged")
	}
	if err := archive.Close(); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, outputAbs); err != nil {
		return err
	}
	succeeded = true
	return nil
}
