package batch

import (
	"context"
	"fmt"
	"os"

	"detonator/internal/config"
	"detonator/internal/detonator"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
	Cyan   = "\033[36m"
)

// RunBatch parses a lockfile and detonates each package sequentially
func RunBatch(ctx context.Context, cfg *config.Config) error {
	fmt.Printf("\n  %s%s📦 NPM Batch Detonator%s\n", Bold, Cyan, Reset)
	fmt.Printf("  %sParsing lockfile: %s%s\n\n", Dim, cfg.Lockfile, Reset)

	targets, err := ParseLockfile(cfg.Lockfile)
	if err != nil {
		return fmt.Errorf("failed to parse lockfile: %w", err)
	}

	total := len(targets)
	if total == 0 {
		fmt.Printf("  %s✓ No dependencies found to detonate.%s\n\n", Green, Reset)
		return nil
	}

	// Apply limit if specified
	if cfg.Limit > 0 && total > cfg.Limit {
		targets = targets[:cfg.Limit]
		fmt.Printf("  %s%s⚠ Found %d dependencies, limiting to first %d%s\n\n", Bold, Yellow, total, cfg.Limit, Reset)
		total = cfg.Limit
	} else {
		fmt.Printf("  %s%sFound %d dependencies to detonate.%s\n\n", Bold, Green, total, Reset)
	}

	successCount := 0
	failureCount := 0

	for i, target := range targets {
		// Check for cancellation
		select {
		case <-ctx.Done():
			fmt.Printf("\n  %s%s⚠ Batch execution cancelled.%s\n", Yellow, Bold, Reset)
			return ctx.Err()
		default:
		}

		fmt.Printf("\n  %s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", Dim, Cyan, Reset)
		fmt.Printf("  %s[%d/%d] DETONATING: %s%s\n", Bold, i+1, total, target.String(), Reset)
		fmt.Printf("  %s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", Dim, Cyan, Reset)

		// Create a copy of the config for this specific detonation
		targetCfg := *cfg
		targetCfg.PackageName = target.String()
		targetCfg.AllowNetwork = true // Required for registry installs

		result, err := detonator.Run(ctx, &targetCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n  %s%s✗ Detonation failed for %s: %v%s\n", Red, Bold, target.String(), err, Reset)
			failureCount++
		} else if !result.Success {
			failureCount++
		} else {
			successCount++
		}
	}

	fmt.Printf("\n  %s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n", Dim, Cyan, Reset)
	fmt.Printf("  %sBATCH COMPLETE%s\n", Bold, Reset)
	fmt.Printf("  %sSuccessful: %d%s\n", Green, successCount, Reset)
	if failureCount > 0 {
		fmt.Printf("  %sFailed:     %d%s\n", Red, failureCount, Reset)
	}
	fmt.Printf("  %s%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n", Dim, Cyan, Reset)

	return nil
}
