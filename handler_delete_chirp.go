package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	tokenClaims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		tokenClaims,
		func(t *jwt.Token) (interface{}, error) { return []byte(cfg.jwtSecret), nil },
	)
	if err != nil {
		respondWithError(w, 401, fmt.Sprintf("An error occured -> %s", err))
		return
	}
	issuer, err := token.Claims.GetIssuer()
	if err != nil {
		respondWithError(w, 500, "Error getting token issuer")
		return
	}
	if issuer != "chirpy-access" {
		respondWithError(w, 401, "Access token required for this action, refresh token given")
		return
	}
	ID, err := token.Claims.GetSubject()
	if err != nil {
		respondWithError(w, 500, "Error parsing user ID from JWT")
		return
	}
	authorID, err := strconv.Atoi(ID)
	if err != nil {
		respondWithError(w, 500, "Error parsing user ID as int")
		return
	}
	chirpIDAsString := chi.URLParam(r, "chirpID")
	chirpID, err := strconv.Atoi(chirpIDAsString)
	if err != nil {
		respondWithError(w, 500, "Error parsing chirp ID as int")
		return
	}
	if chirpID <= 0 {
		respondWithError(w, 500, "Chirp ID must be greater than zero")
		return
	}
	chirp, err := cfg.DB.GetChirp(chirpID)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Something went wrong -> %s", err))
		return
	}
	if chirp.AuthorID != authorID {
		respondWithError(w, 403, "Forbidden action. User did not create this chirp")
		return
	}
	err = cfg.DB.DeleteChirp(chirpID)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Something went wrong -> %s", err))
		return
	}
	respondWithJSON(w, 200, fmt.Sprintf("Successfully deleted chirp with ID %d", chirpID))
}
