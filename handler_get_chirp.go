package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

func (cfg *apiConfig) handlerGetChirp(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "chirpID")
	chirpID, err := strconv.Atoi(id)
	if err != nil {
		respondWithError(w, 500, "Error parsing chirp ID as int")
		return
	}
	if chirpID <= 0 {
		respondWithError(w, 400, "Chirp ID must be greater than zero")
		return
	}
	chirp, err := cfg.DB.GetChirp(chirpID)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
		return
	}
	if chirp.ID == 0 {
		respondWithError(w, 404, fmt.Sprintf("Chirp with ID %s was not found", id))
		return
	}
	respondWithJSON(w, 200, chirp)
}
