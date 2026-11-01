package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

func announce(w *os.File, url, gatewayAddr string) {
	if st, err := w.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		fmt.Fprintf(w, "trafficdeck-web listening on %s (gateway %s)\n", url, gatewayAddr)
		return
	}
	writeBanner(w, url, gatewayAddr, os.Getenv("NO_COLOR") == "")
}

// writeBanner boxes the startup lines. Width is counted in runes and colour is applied after
// padding: both byte lengths and escape codes would throw the right edge out of line.
func writeBanner(w io.Writer, url, gatewayAddr string, colour bool) {
	lines := []string{"TrafficDeck web UI", url, "gateway " + gatewayAddr, "Ctrl-C to stop"}
	width := 0
	for _, l := range lines {
		width = max(width, utf8.RuneCountInString(l))
	}
	rule := strings.Repeat("─", width+2)
	fmt.Fprintf(w, "╭%s╮\n", rule)
	for i, l := range lines {
		padded := l + strings.Repeat(" ", width-utf8.RuneCountInString(l))
		if colour && i == 1 {
			padded = "\x1b[1;36m" + padded + "\x1b[0m"
		}
		fmt.Fprintf(w, "│ %s │\n", padded)
	}
	fmt.Fprintf(w, "╰%s╯\n", rule)
}
