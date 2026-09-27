package terminalui

import "strings"

func WrapWords(text string, width int) []string {
	if width <= 0 {
		width = 80
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return nil
	}
	lines := []string{words[0]}
	for _, word := range words[1:] {
		last := len(lines) - 1
		if len([]rune(lines[last]+" "+word)) <= width {
			lines[last] += " " + word
			continue
		}
		lines = append(lines, word)
	}
	return lines
}
