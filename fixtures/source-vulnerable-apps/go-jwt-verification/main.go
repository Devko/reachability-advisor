package main

import (
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

func handler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	_, _ = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-secret"), nil
	})
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	http.HandleFunc("/token", handler)
	_ = http.ListenAndServe(":8080", nil)
}
