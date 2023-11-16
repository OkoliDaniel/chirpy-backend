package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func (cfg *apiConfig) handlerWebhook(w http.ResponseWriter, r *http.Request) {
	apiKey := strings.TrimPrefix(r.Header.Get("Authorization"), "ApiKey ")
	if apiKey == "" || apiKey != cfg.polkaApiKey {
		respondWithError(w, 401, "")
		return
	}
	defer r.Body.Close()
	type reqBody struct {
		Event string `json:"event"`
		Data  struct {
			UserID int `json:"user_id"`
		} `json:"data"`
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
	if userBody.Event != "user.upgraded" {
		respondWithJSON(w, 200, "")
		return
	}
	ok, err := cfg.DB.UpgradeUser(userBody.Data.UserID)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Something went wrong -> %s", err))
		return
	}
	if !ok {
		respondWithError(w, 404, "User not found")
		return
	}
	respondWithJSON(w, 200, "")
}
