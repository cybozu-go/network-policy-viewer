package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"
)

var (
	ciliumModuleVersion string
)

func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		panic("failed to read build info")
	}
	for _, d := range info.Deps {
		if d.Path == "github.com/cilium/cilium" {
			if d.Replace != nil && d.Replace.Version != "" {
				ciliumModuleVersion = d.Replace.Version
			}
			ciliumModuleVersion = d.Version
			break
		}
	}
}

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

func writeSimpleOrJson(w io.Writer, content any, header []string, count int, values func(index int) []any) error {
	expr := make([][]any, 0)
	for i := range count {
		expr = append(expr, values(i))
	}

	if rootOptions.output == OutputSimple {
		header = slices.Clone(header)
		for j := 0; j < len(header); j++ {
			h := header[j]
			if strings.HasSuffix(h, ":") {
				h = h[:len(h)-1]
				header[j] = h
				width := len(h)
				for i := 0; i < count; i++ {
					v := fmt.Sprintf("%v", expr[i][j])
					width = max(width, len(v))
					expr[i][j] = v
				}

				format := fmt.Sprintf("%%%ds", width)
				header[j] = fmt.Sprintf(format, header[j])
				for i := 0; i < count; i++ {
					expr[i][j] = fmt.Sprintf(format, expr[i][j])
				}
			}
		}
	}

	switch rootOptions.output {
	case OutputJson:
		text, err := json.MarshalIndent(content, "", "  ")
		if err != nil {
			return err
		}
		_, err = w.Write(text)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{'\n'})
		return err
	case OutputSimple:
		tw := tabwriter.NewWriter(w, 0, 1, 1, ' ', 0)
		if !rootOptions.noHeaders {
			if _, err := tw.Write([]byte(strings.Join(header, "\t") + "\n")); err != nil {
				return err
			}
		}
		for i := range count {
			format := strings.Repeat("%v\t", len(header)-1) + "%v\n"
			if _, err := tw.Write([]byte(fmt.Sprintf(format, expr[i]...))); err != nil {
				return err
			}
		}
		return tw.Flush()
	default:
		return fmt.Errorf("unknown format: %s", rootOptions.output)
	}
}
