package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
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
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userBody.Password), bcrypt.DefaultCost)
	if err != nil {
		respondWithError(w, 500, "Error hashing password")
	}
	user, err := cfg.DB.CreateUser(userBody.Email, string(hashedPassword))
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
	}
	if user.ID == 0 {
		respondWithError(w, 409, "User with this email already exists")
		return
	}
	type respBody struct {
		ID          int    `json:"id"`
		Email       string `json:"email"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
	}
	respondWithJSON(w, 201, respBody{ID: user.ID, Email: user.Email, IsChirpyRed: user.IsChirpyRed})
}
