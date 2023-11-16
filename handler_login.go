package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type reqBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type respBody struct {
	ID           int    `json:"id"`
	Email        string `json:"email"`
	IsChirpyRed  bool   `json:"is_chirpy_red"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
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
	user, err := cfg.DB.GetUser(userBody.Email)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
		return
	}
	if user.ID == 0 {
		respondWithError(w, 404, "User not found")
		return
	}
	currentTimeInUTC := time.Now().UTC()
	accessClaims := &jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(currentTimeInUTC),
		ExpiresAt: jwt.NewNumericDate(currentTimeInUTC.Add(1 * time.Hour)),
		Subject:   fmt.Sprint(user.ID),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAcessToken, err := accessToken.SignedString([]byte(cfg.jwtSecret))
	if err != nil {
		respondWithError(w, 500, "Error creating signed access JWT")
		return
	}
	refreshClaims := &jwt.RegisteredClaims{
		Issuer:    "chirpy-refresh",
		IssuedAt:  jwt.NewNumericDate(currentTimeInUTC),
		ExpiresAt: jwt.NewNumericDate(currentTimeInUTC.Add(1440 * time.Hour)),
		Subject:   fmt.Sprint(user.ID),
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	signedRefreshToken, err := refreshToken.SignedString([]byte(cfg.jwtSecret))
	if err != nil {
		respondWithError(w, 500, "Error creating signed refresh JWT")
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userBody.Password))
	if err != nil {
		respondWithError(w, 401, "Incorrect password")
		return
	}
	respondWithJSON(w, 200, respBody{
		ID:           user.ID,
		Email:        user.Email,
		IsChirpyRed:  user.IsChirpyRed,
		Token:        signedAcessToken,
		RefreshToken: signedRefreshToken})
}
