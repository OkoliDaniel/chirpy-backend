package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
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
	if issuer != "chirpy-refresh" {
		respondWithError(w, 401, "Refresh token required for this action, access token given")
		return
	}
	userID, err := token.Claims.GetSubject()
	if err != nil {
		respondWithError(w, 500, "Error parsing user ID from token")
		return
	}
	isRevoked, err := cfg.DB.IsRevokedRefreshToken(tokenString)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
		return
	}
	if isRevoked {
		respondWithError(w, 401, "Action denied, refresh token is revoked")
		return
	}
	currentTimeInUTC := time.Now().UTC()
	accessClaims := &jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(currentTimeInUTC),
		ExpiresAt: jwt.NewNumericDate(currentTimeInUTC.Add(1 * time.Hour)),
		Subject:   userID,
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	signedAcessToken, err := accessToken.SignedString([]byte(cfg.jwtSecret))
	if err != nil {
		respondWithError(w, 500, "Error creating signed access JWT")
		return
	}
	type respBody struct {
		Token string `json:"token"`
	}
	respondWithJSON(w, 200, respBody{Token: signedAcessToken})
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
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
	if issuer != "chirpy-refresh" {
		respondWithError(w, 401, "Refresh token required for this action, access token given")
		return
	}
	err = cfg.DB.AddRevokedRefreshToken(tokenString)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
		return
	}
	w.WriteHeader(200)
}
