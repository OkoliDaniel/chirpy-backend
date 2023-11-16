package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
	tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	tokenClaims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		&tokenClaims,
		func(t *jwt.Token) (interface{}, error) { return []byte(cfg.jwtSecret), nil })
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
	defer r.Body.Close()
	type reqBody struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		respondWithError(w, 500, "Error reading request body")
		return
	}
	userBody := reqBody{}
	err = json.Unmarshal(body, &userBody)
	if err != nil {
		respondWithError(w, 500, "Error unmarshaling JSON")
		return
	}
	ID, err := token.Claims.GetSubject()
	if err != nil {
		respondWithError(w, 500, "Error parsing user ID from JWT")
		return
	}
	userID, err := strconv.Atoi(ID)
	if err != nil {
		respondWithError(w, 500, "Error parsing user ID as int")
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userBody.Password), bcrypt.DefaultCost)
	if err != nil {
		respondWithError(w, 500, "Error hashing password")
		return
	}
	user, err := cfg.DB.UpdateUser(userID, userBody.Email, string(hashedPassword))
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
		return
	}
	if user.ID == 0 {
		respondWithError(w, 404, "User not found")
		return
	}
	respondWithJSON(w, 200, respBody{ID: user.ID, Email: user.Email, IsChirpyRed: user.IsChirpyRed})
}
