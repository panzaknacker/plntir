package main

import (
	"flag"
	"fmt"
	"os"

	"plntir/core/internal/lambdapack"
)

func main() {
	input := flag.String("input", "", "compiled custom-runtime Lambda binary")
	output := flag.String("output", "", "destination ZIP path")
	flag.Parse()
	if flag.NArg() != 0 || *input == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: plntir-lambda-pack -input BINARY -output ARCHIVE.zip")
		os.Exit(2)
	}
	if err := lambdapack.Pack(*input, *output); err != nil {
		fmt.Fprintln(os.Stderr, "plntir-lambda-pack:", err)
		os.Exit(1)
	}
}
