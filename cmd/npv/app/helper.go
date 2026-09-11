package app

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

func formatWithUnits(v uint64) string {
	if v < 1024 || !rootOptions.units {
		return fmt.Sprint(v)
	}

	units := "_KMGTPEZY"
	i := 0
	fv := float64(v)
	for fv >= 1024 {
		i += 1
		fv /= 1024
	}
	return fmt.Sprintf("%.1f%c", fv, units[i])
}

func computeAverage(bytes, count uint64) float64 {
	if count == 0 {
		return 0
	}
	return float64(bytes) / float64(count)
}

// formatStatsColumns returns the BYTES/REQUESTS/AVERAGE column values for an
// inspectEntry. It shows "-" for all three when the underlying policy map
// entry's statistics were not available (see proxy.PolicyEntry.IsStatsAvailable),
// rather than printing a computed value derived from a zeroed-out placeholder.
func formatStatsColumns(p inspectEntry) (bytesStr, requestsStr, avgStr string) {
	if !p.StatsAvailable {
		return "-", "-", "-"
	}
	avgStr = fmt.Sprintf("%.1f", computeAverage(p.Bytes, p.Requests))
	return formatWithUnits(p.Bytes), formatWithUnits(p.Requests), avgStr
}

func colored(color int, text string) string {
	if color != 0 && term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Sprintf("\x1b[1;%dm"+"%s"+"\x1b[0m", color, text)
	}
	return text
}
