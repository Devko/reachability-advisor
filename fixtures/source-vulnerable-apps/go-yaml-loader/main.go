package main

import (
	"net/http"

	"gopkg.in/yaml.v3"
)

type payload struct {
	Name string `yaml:"name"`
}

func handler(w http.ResponseWriter, r *http.Request) {
	var body payload
	_ = yaml.Unmarshal([]byte(r.URL.Query().Get("document")), &body)
	_, _ = w.Write([]byte(body.Name))
}

func main() {
	http.HandleFunc("/load", handler)
	_ = http.ListenAndServe(":8080", nil)
}
