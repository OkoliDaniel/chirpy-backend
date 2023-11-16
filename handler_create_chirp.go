package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func isValidChirp(chirp string) bool {
	maxChirpLength := 140
	return len(chirp) <= maxChirpLength
}

func cleanChirp(chirp string) string {
	words := strings.Split(chirp, " ")
	profanities := []string{"kerfuffle", "sharbert", "fornax"}
	for i, word := range words {
		if slices.Contains[[]string, string](profanities, strings.ToLower(word)) {
			words[i] = "****"
		}
	}
	cleanedChirp := strings.Join(words, " ")
	return cleanedChirp
}

func (cfg *apiConfig) handlerCreateChirp(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
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

	type reqBody struct {
		Body string `json:"body"`
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, 500, "Error reading request body")
		return
	}
	chrp := reqBody{}
	err = json.Unmarshal(body, &chrp)
	if err != nil {
		respondWithError(w, 500, "Error unmarshaling JSON")
		return
	}
	if isValidChirp(chrp.Body) {
		chirp, err := cfg.DB.CreateChirp(cleanChirp(chrp.Body), authorID)
		if err != nil {
			respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
			return
		}
		respondWithJSON(w, 201, chirp)
		return
	}
	respondWithError(w, 400, "Chirp is too long")
}
