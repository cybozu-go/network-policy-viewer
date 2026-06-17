package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"text/tabwriter"

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

// inflateRow expands a single row into multiple rows when some cells contain slices.
func inflateRow(input []any, repeat []bool) [][]any {
	// Input:
	// a | [1, 2] | [100, 200, 300]
	//
	// Output:
	// a | 1 | 100
	//   | 2 | 200
	//   |   | 300
	ncol := len(input)
	maxHeight := 1
	height := make([]int, ncol)
	inflate := make([]bool, ncol)
	for i := range ncol {
		if reflect.TypeOf(input[i]).Kind() == reflect.Slice {
			height[i] = reflect.ValueOf(input[i]).Len()
			maxHeight = max(maxHeight, height[i])
			inflate[i] = true
		}
	}

	ret := make([][]any, maxHeight)
	for j := range maxHeight {
		entry := make([]any, ncol)
		for i := range ncol {
			switch {
			case repeat[i]:
				fallthrough
			case (j == 0) && !inflate[i]:
				entry[i] = input[i]
			case j < height[i]:
				v := reflect.ValueOf(input[i]).Index(j).Interface()
				entry[i] = v
			default:
				entry[i] = ""
			}
		}
		ret[j] = entry
	}
	return ret
}

func writeSimpleOrJson(w io.Writer, content any, header []string, count int, values func(index int) []any) error {
	expr := make([][]any, 0)
	if rootOptions.output == OutputSimple {
		repeat := make([]bool, len(header))
		for i := range len(header) {
			repeat[i] = header[i] == "|"
		}

		for i := range count {
			v := values(i)
			entries := inflateRow(v, repeat)
			expr = append(expr, entries...)
		}

		header = slices.Clone(header)
		for j := 0; j < len(header); j++ {
			h := header[j]
			if strings.HasSuffix(h, ":") {
				h = h[:len(h)-1]
				header[j] = h
				width := len(h)
				for i := range len(expr) {
					v := fmt.Sprintf("%v", expr[i][j])
					width = max(width, len(v))
					expr[i][j] = v
				}

				format := fmt.Sprintf("%%%ds", width)
				header[j] = fmt.Sprintf(format, header[j])
				for i := range len(expr) {
					expr[i][j] = fmt.Sprintf(format, expr[i][j])
				}
			}
		}
	} else {
		for i := range count {
			expr = append(expr, values(i))
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
		for i := range len(expr) {
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
