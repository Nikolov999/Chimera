package terminalui

import (
	"fmt"
	"strings"
)

const (
	BannerSubtitle        = "Live Host Vulnerability & Exposure Assessment"
	BannerOperationalLine = "Local • Read-only • Evidence-backed"
	fullBannerMinWidth    = 52
)

const fullBannerArt = `   ________  __  ________  __________  ___
  / ____/ / / / /  _/  |/  / ____/ / / /
 / /   / /_/ /  / // /|_/ / __/ / /_/ /
/ /___/ __  / _/ // /  / / /___/ __  /
\____/_/ /_/ /___/_/  /_/_____/_/ /_/`

const compactBannerArt = `CHIMERA`

func BannerText(ctx Context, version string) string {
	if !ctx.Banner || ctx.Machine {
		return ""
	}
	art := fullBannerArt
	if ctx.Width > 0 && ctx.Width < fullBannerMinWidth {
		art = compactBannerArt
	}
	if ctx.ColorMode != ColorPlain {
		if art == compactBannerArt {
			art = GradientByRune(art, ctx.ColorMode)
		} else {
			art = GradientByLine(art, ctx.ColorMode)
		}
	}
	var b strings.Builder
	b.WriteString(art)
	b.WriteByte('\n')
	b.WriteString(Accent(BannerSubtitle, ctx.ColorMode))
	b.WriteByte('\n')
	b.WriteString(Dim(BannerOperationalLine, ctx.ColorMode))
	b.WriteByte('\n')
	if strings.TrimSpace(version) != "" {
		b.WriteString(Dim(fmt.Sprintf("Version %s", strings.TrimSpace(version)), ctx.ColorMode))
		b.WriteByte('\n')
	}
	return b.String()
}

func FullBannerArt() string    { return fullBannerArt }
func CompactBannerArt() string { return compactBannerArt }
