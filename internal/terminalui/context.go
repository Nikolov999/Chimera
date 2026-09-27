package terminalui

import (
	"io"
	"os"
	"strconv"
	"strings"
)

type ColorMode uint8

const (
	ColorPlain ColorMode = iota
	ColorANSI16
	ColorANSI256
	ColorTrueColor
)

type Options struct {
	JSON    bool
	Plain   bool
	NoColor bool
	Quiet   bool
	TTY     *bool
	Width   int
}

type Context struct {
	TTY        bool
	Redirected bool
	Machine    bool
	Banner     bool
	Width      int
	ColorMode  ColorMode
}

func New(w io.Writer, opts Options) Context {
	tty := detectTTY(w)
	if opts.TTY != nil {
		tty = *opts.TTY
	}
	width := 0
	if tty {
		width = terminalWidth()
		if opts.Width > 0 {
			width = opts.Width
		}
	}
	mode := detectColorMode(tty, opts.NoColor || opts.Plain || opts.JSON)
	return Context{
		TTY:        tty,
		Redirected: !tty,
		Machine:    opts.JSON,
		Banner:     tty && !opts.JSON && !opts.Quiet,
		Width:      width,
		ColorMode:  mode,
	}
}

func detectTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func terminalWidth() int {
	if raw := strings.TrimSpace(os.Getenv("COLUMNS")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
			return n
		}
	}
	return 80
}

func detectColorMode(tty bool, disabled bool) ColorMode {
	if !tty || disabled || os.Getenv("NO_COLOR") != "" || strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") {
		return ColorPlain
	}
	ct := strings.ToLower(strings.TrimSpace(os.Getenv("COLORTERM")))
	term := strings.ToLower(strings.TrimSpace(os.Getenv("TERM")))
	if strings.Contains(ct, "truecolor") || strings.Contains(ct, "24bit") || os.Getenv("WT_SESSION") != "" || strings.Contains(term, "direct") || strings.Contains(term, "truecolor") {
		return ColorTrueColor
	}
	if strings.Contains(term, "256color") {
		return ColorANSI256
	}
	return ColorANSI16
}
