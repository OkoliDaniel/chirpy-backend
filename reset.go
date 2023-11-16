package main

import (
	"net/http"
)

func (cfg *apiConfig) resetFileServerHits(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits = 0
	w.WriteHeader(200)
}
