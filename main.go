package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"internal/database"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

func middlewareCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type apiConfig struct {
	fileserverHits int
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits++
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) sendFileServerHits(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(fmt.Sprintf(`<html>

	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited <strong>%d</strong> times!</p>
	</body>
	
	</html>
	`, cfg.fileserverHits)))
}

func (cfg *apiConfig) resetFileServerHits(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits = 0
	w.WriteHeader(200)
}

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

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	respBody, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshaling JSON: %s\n", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(respBody)
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type errorResp struct {
		Error string `json:"error"`
	}
	respondWithJSON(w, code, errorResp{Error: msg})
	log.Println(msg)
}

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

func main() {
	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
	polkaAPiKey := os.Getenv("POLKA_API_KEY")
	db, err := database.NewDB("database.json")
	if err != nil {
		log.Fatalf("Error preparing database: %s", err)
	}
	mux := chi.NewRouter()
	apiMux := chi.NewRouter()
	adminMux := chi.NewRouter()
	//mux := http.NewServeMux()
	corsMux := middlewareCors(mux)
	//mux.Handle("/app/", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	//mux.Handle("/assets/logo.png", http.FileServer(http.Dir(".")))
	cfgPtr := &apiConfig{
		fileserverHits: 0,
	}
	//fsHandler := http.StripPrefix("/app", http.FileServer(http.Dir(".")))
	//mux.Handle("/app/", cfgPtr.middlewareMetricsInc(fsHandler))
	fsHandler := cfgPtr.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	mux.Handle("/app/*", fsHandler)
	mux.Handle("/app", fsHandler)
	mux.Handle("/app/assets", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	adminMux.Get("/metrics", cfgPtr.sendFileServerHits)
	apiMux.HandleFunc("/reset", cfgPtr.resetFileServerHits)
	apiMux.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})
	apiMux.Post("/chirps", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tokenClaims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(
			tokenString,
			tokenClaims,
			func(t *jwt.Token) (interface{}, error) { return []byte(jwtSecret), nil },
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
			chirp, err := db.CreateChirp(cleanChirp(chrp.Body), authorID)
			if err != nil {
				respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
				return
			}
			respondWithJSON(w, 201, chirp)
			return
		}
		respondWithError(w, 400, "Chirp is too long")
	})
	apiMux.Get("/chirps", func(w http.ResponseWriter, r *http.Request) {
		authorIDAsString := r.URL.Query().Get("author_id")
		value := r.URL.Query().Get("sort")
		var sortKey Sortkey
		if value == "" || !(value == "asc" || value == "desc") || value == "asc" {
			sortKey = asc
		} else {
			sortKey = desc
		}
		if authorIDAsString == "" {
			chirps, err := db.GetChirps()
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
		chirps, err := db.GetChirpsByAuthorID(authorID)
		if err != nil {
			respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
			return
		}
		chirps = sortChirpsByAuthorID(sortKey, chirps)
		respondWithJSON(w, 200, chirps)
	})
	apiMux.Get("/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "chirpID")
		chirpID, _ := strconv.Atoi(id)
		if err != nil {
			respondWithError(w, 500, "Error parsing chirp ID as int")
			return
		}
		if chirpID <= 0 {
			respondWithError(w, 400, "Chirp ID must be greater than zero")
			return
		}
		chirp, err := db.GetChirp(chirpID)
		if err != nil {
			respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
			return
		}
		if chirp.ID == 0 {
			respondWithError(w, 404, fmt.Sprintf("Chirp with ID %s was not found", id))
			return
		}
		respondWithJSON(w, 200, chirp)
	})
	apiMux.Delete("/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tokenClaims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(
			tokenString,
			tokenClaims,
			func(t *jwt.Token) (interface{}, error) { return []byte(jwtSecret), nil },
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
		chirp, err := db.GetChirp(chirpID)
		if err != nil {
			respondWithError(w, 500, fmt.Sprintf("Something went wrong -> %s", err))
			return
		}
		if chirp.AuthorID != authorID {
			respondWithError(w, 403, "Forbidden action. User did not create this chirp")
			return
		}
		err = db.DeleteChirp(chirpID)
		if err != nil {
			respondWithError(w, 500, fmt.Sprintf("Something went wrong -> %s", err))
			return
		}
		respondWithJSON(w, 200, fmt.Sprintf("Successfully deleted chirp with ID %d", chirpID))
	})

	apiMux.Post("/users", func(w http.ResponseWriter, r *http.Request) {
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
		user, err := db.CreateUser(userBody.Email, string(hashedPassword))
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
	})
	apiMux.Post("/login", func(w http.ResponseWriter, r *http.Request) {
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
		user, err := db.GetUser(userBody.Email)
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
		signedAcessToken, err := accessToken.SignedString([]byte(jwtSecret))
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
		signedRefreshToken, err := refreshToken.SignedString([]byte(jwtSecret))
		if err != nil {
			respondWithError(w, 500, "Error creating signed refresh JWT")
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userBody.Password))
		if err != nil {
			respondWithError(w, 401, "Incorrect password")
			return
		}
		type respBody struct {
			ID           int    `json:"id"`
			Email        string `json:"email"`
			IsChirpyRed  bool   `json:"is_chirpy_red"`
			Token        string `json:"token"`
			RefreshToken string `json:"refresh_token"`
		}
		respondWithJSON(w, 200, respBody{
			ID:           user.ID,
			Email:        user.Email,
			IsChirpyRed:  user.IsChirpyRed,
			Token:        signedAcessToken,
			RefreshToken: signedRefreshToken})
	})
	apiMux.Put("/users", func(w http.ResponseWriter, r *http.Request) {
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tokenClaims := jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(
			tokenString,
			&tokenClaims,
			func(t *jwt.Token) (interface{}, error) { return []byte(jwtSecret), nil })
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
		user, err := db.UpdateUser(userID, userBody.Email, string(hashedPassword))
		if err != nil {
			respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
			return
		}
		if user.ID == 0 {
			respondWithError(w, 404, "User not found")
			return
		}
		type respBody struct {
			ID          int    `json:"id"`
			Email       string `json:"email"`
			IsChirpyRed bool   `json:"is_chirpy_red"`
		}
		respondWithJSON(w, 200, respBody{ID: user.ID, Email: user.Email, IsChirpyRed: user.IsChirpyRed})
	})
	apiMux.Post("/polka/webhooks", func(w http.ResponseWriter, r *http.Request) {
		apiKey := strings.TrimPrefix(r.Header.Get("Authorization"), "ApiKey ")
		if apiKey == "" || apiKey != polkaAPiKey {
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
		ok, err := db.UpgradeUser(userBody.Data.UserID)
		if err != nil {
			respondWithError(w, 500, fmt.Sprintf("Something went wrong -> %s", err))
			return
		}
		if !ok {
			respondWithError(w, 404, "User not found")
			return
		}
		respondWithJSON(w, 200, "")
	})
	apiMux.Post("/refresh", func(w http.ResponseWriter, r *http.Request) {
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tokenClaims := jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(
			tokenString,
			&tokenClaims,
			func(t *jwt.Token) (interface{}, error) { return []byte(jwtSecret), nil })
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
		isRevoked, err := db.IsRevokedRefreshToken(tokenString)
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
		signedAcessToken, err := accessToken.SignedString([]byte(jwtSecret))
		if err != nil {
			respondWithError(w, 500, "Error creating signed access JWT")
			return
		}
		type respBody struct {
			Token string `json:"token"`
		}
		respondWithJSON(w, 200, respBody{Token: signedAcessToken})
	})
	apiMux.Post("/revoke", func(w http.ResponseWriter, r *http.Request) {
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tokenClaims := jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(
			tokenString,
			&tokenClaims,
			func(t *jwt.Token) (interface{}, error) { return []byte(jwtSecret), nil })
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
		err = db.AddRevokedRefreshToken(tokenString)
		if err != nil {
			respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
			return
		}
		w.WriteHeader(200)
	})

	mux.Mount("/api/", apiMux)
	mux.Mount("/admin/", adminMux)
	server := http.Server{
		Addr:    "localhost:8080",
		Handler: corsMux,
	}
	log.Println("Starting server on localhost at port 8080")
	err = server.ListenAndServe()
	log.Fatal(err)
}
