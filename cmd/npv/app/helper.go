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

func colored(color int, text string) string {
	if color != 0 && term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Sprintf("\x1b[1;%dm"+"%s"+"\x1b[0m", color, text)
	}
	return text
}
