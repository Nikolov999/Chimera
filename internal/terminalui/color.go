package terminalui

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

type rgb struct{ r, g, b int }

var (
	// Chimera's green product gradient: deep emerald through electric green.
	chimeraStart  = rgb{r: 0, g: 105, b: 62}
	chimeraEnd    = rgb{r: 94, g: 255, b: 148}
	chimeraAccent = rgb{r: 20, g: 220, b: 100}
)

func GradientByLine(s string, mode ColorMode) string {
	if mode == ColorPlain || s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	var b strings.Builder
	for i, line := range lines {
		c := interpolate(chimeraStart, chimeraEnd, i, max(1, len(lines)-1))
		b.WriteString(paintRGB(line, c, mode))
		if i != len(lines)-1 {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func GradientByRune(s string, mode ColorMode) string {
	if mode == ColorPlain || s == "" {
		return s
	}
	count := utf8.RuneCountInString(s)
	var b strings.Builder
	i := 0
	for _, r := range s {
		if r == '\n' {
			b.WriteRune(r)
			continue
		}
		c := interpolate(chimeraStart, chimeraEnd, i, max(1, count-1))
		b.WriteString(paintRGB(string(r), c, mode))
		i++
	}
	return b.String()
}

func Accent(s string, mode ColorMode) string {
	return paintRGB(s, chimeraAccent, mode)
}

func Dim(s string, mode ColorMode) string {
	if mode == ColorPlain || s == "" {
		return s
	}
	return "\x1b[2m" + s + "\x1b[0m"
}

func paintRGB(s string, c rgb, mode ColorMode) string {
	if s == "" || mode == ColorPlain {
		return s
	}
	switch mode {
	case ColorTrueColor:
		return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s\x1b[0m", c.r, c.g, c.b, s)
	case ColorANSI256:
		return fmt.Sprintf("\x1b[38;5;%dm%s\x1b[0m", rgbTo256(c), s)
	default:
		return "\x1b[92m" + s + "\x1b[0m"
	}
}

func interpolate(a, b rgb, i, n int) rgb {
	if n <= 0 {
		return a
	}
	return rgb{
		r: a.r + (b.r-a.r)*i/n,
		g: a.g + (b.g-a.g)*i/n,
		b: a.b + (b.b-a.b)*i/n,
	}
}

func rgbTo256(c rgb) int {
	to6 := func(v int) int { return (v*5 + 127) / 255 }
	return 16 + 36*to6(c.r) + 6*to6(c.g) + to6(c.b)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
