package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"detonator/internal/config"
	"detonator/internal/detonator"
	"detonator/internal/orchestrator"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
)

func main() {
	// CLI flags
	packageName := flag.String("package", "", "NPM package name to detonate (e.g., lodash, express)")
	registry := flag.String("registry", "npm", "Package registry: npm or pypi")
	timeout := flag.Duration("timeout", 30*time.Second, "Detonation timeout duration")
	memLimit := flag.Int64("memory", 256, "Container memory limit in MB")
	pidsLimit := flag.Int64("pids", 100, "Container PID limit")
	kafkaBroker := flag.String("kafka-broker", "localhost:9092", "Kafka broker address (empty to disable)")
	localPackage := flag.String("local-package", "", "Path to a local .tgz package to detonate")
	testDocker := flag.Bool("test-docker", false, "Test Docker daemon connectivity and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\n  %s%s☢  NPM Supply Chain Detonation Sandbox%s\n\n", Bold, Red, Reset)
		fmt.Fprintf(os.Stderr, "  %sUsage:%s\n", Bold, Reset)
		fmt.Fprintf(os.Stderr, "    detonator --package <name> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "  %sExamples:%s\n", Bold, Reset)
		fmt.Fprintf(os.Stderr, "    detonator --package lodash                  %s# Detonate lodash (safe test)%s\n", Dim, Reset)
		fmt.Fprintf(os.Stderr, "    detonator --package suspicious-pkg          %s# Detonate unknown package%s\n", Dim, Reset)
		fmt.Fprintf(os.Stderr, "    detonator --package express --timeout 60s   %s# Extended detonation window%s\n", Dim, Reset)
		fmt.Fprintf(os.Stderr, "    detonator --package evil --local-package ./evil-pkg-1.0.0.tgz  %s# Detonate local tarball%s\n", Dim, Reset)
		fmt.Fprintf(os.Stderr, "    detonator --test-docker                     %s# Verify Docker connectivity%s\n", Dim, Reset)
		fmt.Fprintf(os.Stderr, "\n  %sFlags:%s\n", Bold, Reset)
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr)
	}

	flag.Parse()

	// Handle Docker connectivity test
	if *testDocker {
		runDockerTest()
		return
	}

	// Validate required flags
	if *packageName == "" {
		fmt.Fprintf(os.Stderr, "\n  %s%s✗ Error:%s --package flag is required\n", Red, Bold, Reset)
		fmt.Fprintf(os.Stderr, "  %sRun 'detonator --help' for usage info%s\n\n", Dim, Reset)
		os.Exit(1)
	}

	// Validate registry
	reg := config.Registry(*registry)
	if reg != config.NPM && reg != config.PyPI {
		fmt.Fprintf(os.Stderr, "\n  %s%s✗ Error:%s invalid registry '%s' (must be 'npm' or 'pypi')\n\n", Red, Bold, Reset, *registry)
		os.Exit(1)
	}

	// Build config
	cfg := config.DefaultConfig()
	cfg.PackageName = *packageName
	cfg.Registry = reg
	cfg.DetonationTimeout = *timeout
	cfg.MemoryLimitMB = *memLimit
	cfg.PidsLimit = *pidsLimit
	cfg.KafkaBroker = *kafkaBroker
	cfg.LocalPackage = *localPackage

	// Context with signal handling (Ctrl+C → graceful shutdown)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		fmt.Printf("\n\n  %s%s⚠ Caught %s — initiating emergency shutdown...%s\n", Yellow, Bold, sig, Reset)
		cancel()
	}()

	// Run detonation
	result, err := detonator.Run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n  %s%s✗ Detonation failed: %s%s\n\n", Red, Bold, err, Reset)
		os.Exit(1)
	}

	if !result.Success {
		os.Exit(1)
	}
}

func runDockerTest() {
	fmt.Printf("\n  %sTesting Docker daemon connectivity...%s\n\n", Bold, Reset)

	cfg := config.DefaultConfig()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Printf("  %s[1/2]%s Creating Docker client...", Yellow, Reset)
	orch, err := orchestrator.New(cfg)
	if err != nil {
		fmt.Printf("  %s✗%s  %s\n", Red, Reset, err)
		fmt.Printf("\n  %s%sFix:%s Make sure Docker Desktop is running and WSL integration is enabled%s\n\n", Yellow, Bold, Reset, Reset)
		os.Exit(1)
	}
	defer orch.Close()
	fmt.Printf("  %s✓%s\n", Green, Reset)

	fmt.Printf("  %s[2/2]%s Pinging Docker daemon...", Yellow, Reset)
	if err := orch.Ping(ctx); err != nil {
		fmt.Printf("  %s✗%s  %s\n", Red, Reset, err)
		fmt.Printf("\n  %s%sFix:%s Make sure Docker Desktop is running and WSL integration is enabled%s\n\n", Yellow, Bold, Reset, Reset)
		os.Exit(1)
	}
	fmt.Printf("  %s✓%s\n", Green, Reset)

	fmt.Printf("\n  %s%s✓ Docker daemon is reachable. Ready to detonate.%s\n\n", Green, Bold, Reset)
}
