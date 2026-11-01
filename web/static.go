package main

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// all: so the committed dist/.gitkeep satisfies the pattern before any bundle is built.
//
//go:embed all:dist
var embedded embed.FS

const stubPage = `<!doctype html><meta charset="utf-8"><title>TrafficDeck</title>
<p>The web UI bundle was not built. Install node and run <code>make build</code>.</p>`

// staticHandler serves the bundle and sends unknown paths to index.html. It is embedded
// because a viewer is spawned with no meaningful working directory.
func staticHandler(files fs.FS) http.Handler {
	fileServer := http.FileServerFS(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if st, err := fs.Stat(files, name); err == nil && !st.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}
		index, err := fs.ReadFile(files, "index.html")
		if err != nil {
			index = []byte(stubPage)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
}

func bundle() fs.FS {
	dist, err := fs.Sub(embedded, "dist")
	if err != nil {
		panic(err) // the pattern above is a compile-time constant
	}
	return dist
}
