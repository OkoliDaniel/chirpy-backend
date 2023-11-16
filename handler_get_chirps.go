package main

import (
	"fmt"
	"internal/database"
	"net/http"
	"sort"
	"strconv"
)

type Sortkey string

const (
	asc  Sortkey = "asc"
	desc Sortkey = "desc"
)

func sortChirpsByAuthorID(sortKey Sortkey, chirps []database.Chirp) []database.Chirp {
	if sortKey == asc {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].AuthorID < chirps[j].AuthorID
		})
		return chirps
	}
	sort.Slice(chirps, func(i, j int) bool { return chirps[i].AuthorID > chirps[j].AuthorID })
	reversedChirps := make([]database.Chirp, 0, len(chirps))
	for i := len(chirps) - 1; i >= 0; i-- {
		reversedChirps = append(reversedChirps, chirps[i])
	}
	return reversedChirps
}

func (cfg *apiConfig) handlerGetChirps(w http.ResponseWriter, r *http.Request) {
	authorIDAsString := r.URL.Query().Get("author_id")
	value := r.URL.Query().Get("sort")
	var sortKey Sortkey
	if value == "" || !(value == "asc" || value == "desc") || value == "asc" {
		sortKey = asc
	} else {
		sortKey = desc
	}
	if authorIDAsString == "" {
		chirps, err := cfg.DB.GetChirps()
		if err != nil {
			respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
			return
		}
		chirps = sortChirpsByAuthorID(sortKey, chirps)
		respondWithJSON(w, 200, chirps)
		return
	}
	authorID, err := strconv.Atoi(authorIDAsString)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
		return
	}
	if authorID <= 0 {
		respondWithError(w, 400, "Author ID must be greater than zero")
		return
	}
	chirps, err := cfg.DB.GetChirpsByAuthorID(authorID)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
		return
	}
	chirps = sortChirpsByAuthorID(sortKey, chirps)
	respondWithJSON(w, 200, chirps)
}
