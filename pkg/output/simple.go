package output

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"text/tabwriter"
)

const (
	FormatJson   = "json"
	FormatSimple = "simple"
)

type Config struct {
	Format    string
	NoHeaders bool
}

var config *Config

func GetConfig() *Config {
	return config
}

func SetConfig(c *Config) {
	config = c
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

func WriteSimpleOrJson(w io.Writer, content any, header []string, count int, values func(index int) []any) error {
	expr := make([][]any, 0)
	if config.Format == FormatSimple {
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

	switch config.Format {
	case FormatJson:
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
	case FormatSimple:
		tw := tabwriter.NewWriter(w, 0, 1, 1, ' ', 0)
		if !config.NoHeaders {
			if _, err := tw.Write([]byte(strings.Join(header, "\t") + "\n")); err != nil {
				return err
			}
		}
		for i := range len(expr) {
			format := strings.Repeat("%v\t", len(header)-1) + "%v\n"
			fmt.Fprintf(tw, format, expr[i]...)
		}
		return tw.Flush()
	default:
		return fmt.Errorf("unknown format: %s", config.Format)
	}
}
