package terminalui

import (
	"io"
	"strings"
	"unicode"
)

// HeaderWriter adds Chimera's brand accent to existing human-renderer section
// headings without changing domain renderers or machine output contracts.
type HeaderWriter struct {
	w       io.Writer
	mode    ColorMode
	pending string
}

func NewHeaderWriter(w io.Writer, mode ColorMode) *HeaderWriter {
	return &HeaderWriter{w: w, mode: mode}
}

func (h *HeaderWriter) Write(p []byte) (int, error) {
	if h.mode == ColorPlain {
		return h.w.Write(p)
	}
	h.pending += string(p)
	consumed := len(p)
	for {
		idx := strings.IndexByte(h.pending, '\n')
		if idx < 0 {
			break
		}
		line := h.pending[:idx]
		h.pending = h.pending[idx+1:]
		if _, err := io.WriteString(h.w, h.styleLine(line)+"\n"); err != nil {
			return 0, err
		}
	}
	return consumed, nil
}

func (h *HeaderWriter) Flush() error {
	if h.pending == "" {
		return nil
	}
	_, err := io.WriteString(h.w, h.styleLine(h.pending))
	h.pending = ""
	return err
}

func (h *HeaderWriter) styleLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if line != trimmed || trimmed == "" || strings.Contains(trimmed, "\x1b[") || !hasLetter(trimmed) || strings.ToUpper(trimmed) != trimmed {
		return line
	}
	return Accent(line, h.mode)
}

func hasLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}
