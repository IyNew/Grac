package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	iterations = flag.Int("iterations", 10, "Number of iterations for benchmarking")
	verbose    = flag.Bool("verbose", false, "Verbose output")
)

func main() {
	flag.Parse()

	if *verbose {
		fmt.Println("Running combined circuit benchmark with verbose output...")
	}

	runCombinedBenchmark()
}


