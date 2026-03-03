package logscan

import (
	"bufio"
	"io"
	"os"
	"strings"
)

const (
	// DefaultMaxLineBytes is intentionally large to support JSONL records that
	// embed sizeable aggregated command output.
	DefaultMaxLineBytes = 16 * 1024 * 1024
)

// ForEachLine opens path and invokes fn for each logical line.
//
// Lines longer than maxLineBytes are skipped (and counted) so callers can keep
// processing without failing the whole scan.
//
// If fn returns false, scanning stops early and nil is returned.
func ForEachLine(path string, maxLineBytes int, fn func(string) bool) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return ForEachLineReader(f, maxLineBytes, fn)
}

// ForEachLineReader scans r line-by-line with overflow protection.
func ForEachLineReader(r io.Reader, maxLineBytes int, fn func(string) bool) (int, error) {
	if maxLineBytes <= 0 {
		maxLineBytes = DefaultMaxLineBytes
	}
	br := bufio.NewReaderSize(r, 64*1024)

	buf := make([]byte, 0, 64*1024)
	discarding := false
	skipped := 0

	flush := func() bool {
		if discarding {
			discarding = false
			buf = buf[:0]
			return true
		}
		line := strings.TrimSpace(string(buf))
		buf = buf[:0]
		if line == "" {
			return true
		}
		return fn(line)
	}

	for {
		chunk, err := br.ReadSlice('\n')
		hasNewline := len(chunk) > 0 && chunk[len(chunk)-1] == '\n'

		if len(chunk) > 0 {
			if !discarding {
				if len(buf)+len(chunk) > maxLineBytes {
					discarding = true
					skipped++
				} else {
					buf = append(buf, chunk...)
				}
			}
		}

		if hasNewline {
			if !flush() {
				return skipped, nil
			}
		}

		if err == nil {
			continue
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			if len(buf) > 0 || discarding {
				if !flush() {
					return skipped, nil
				}
			}
			return skipped, nil
		}
		return skipped, err
	}
}
