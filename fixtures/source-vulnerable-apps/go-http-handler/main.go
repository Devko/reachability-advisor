package main

import (
	"io"
	"net/http"
)

func main() {
	http.HandleFunc("/proxy", func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(r.URL.Query().Get("url"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	})
	http.ListenAndServe(":8080", nil)
}
