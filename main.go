package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
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

func main() {
	godotenv.Load()
	jwtSecret := os.Getenv("JWT_SECRET")
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
			chirp, err := db.CreateChirp(cleanChirp(chrp.Body))
			if err != nil {
				respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
				return
			}
			respondWithJSON(w, 201, chirp)
		} else {
			respondWithError(w, 400, "Chirp is too long")
		}
	})
	apiMux.Get("/chirps", func(w http.ResponseWriter, r *http.Request) {
		chirps, err := db.GetChirps()
		if err != nil {
			respondWithError(w, 500, fmt.Sprintf("Something went wrong: %s", err))
			return
		}
		respondWithJSON(w, 200, chirps)
	})
	apiMux.Get("/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "chirpID")
		chirpID, _ := strconv.Atoi(id)
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
			ID    int    `json:"id"`
			Email string `json:"email"`
		}
		respondWithJSON(w, 201, respBody{ID: user.ID, Email: user.Email})
	})
	apiMux.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		type reqBody struct {
			Email            string `json:"email"`
			Password         string `json:"password"`
			ExpiresInSeconds int    `json:"expires_in_seconds"`
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
		var expiresInSeconds int
		secondsInADay := 86400
		if userBody.ExpiresInSeconds == 0 || userBody.ExpiresInSeconds > secondsInADay {
			expiresInSeconds = secondsInADay
		} else if userBody.ExpiresInSeconds > 0 {
			expiresInSeconds = userBody.ExpiresInSeconds
		}
		currentTimeInUTC := time.Now().UTC()
		expirationAsDuration, err := time.ParseDuration(fmt.Sprintf("%ds", expiresInSeconds))
		if err != nil {
			respondWithError(w, 500, "Error parsing expiration time as time.Duration")
			return
		}
		claims := &jwt.RegisteredClaims{
			Issuer:    "chirpy",
			IssuedAt:  jwt.NewNumericDate(currentTimeInUTC),
			ExpiresAt: jwt.NewNumericDate(currentTimeInUTC.Add(expirationAsDuration)),
			Subject:   fmt.Sprint(user.ID),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signedToken, err := token.SignedString([]byte(jwtSecret))
		if err != nil {
			respondWithError(w, 500, "Error creating signed JWT")
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(userBody.Password))
		if err != nil {
			respondWithError(w, 401, "Incorrect password")
			return
		}
		type respBody struct {
			ID    int    `json:"id"`
			Email string `json:"email"`
			Token string `json:"token"`
		}
		respondWithJSON(w, 200, respBody{ID: user.ID, Email: user.Email, Token: signedToken})
	})
	apiMux.Put("/users", func(w http.ResponseWriter, r *http.Request) {
		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		log.Printf("Recieved JWT: %s", tokenString)
		tokenClaims := jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(
			tokenString,
			&tokenClaims,
			func(t *jwt.Token) (interface{}, error) { return []byte(jwtSecret), nil })
		if err != nil {
			respondWithError(w, 401, fmt.Sprintf("Error parsing JWT object from token string -> %s", err))
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
			ID    int    `json:"id"`
			Email string `json:"email"`
		}
		respondWithJSON(w, 200, respBody{ID: user.ID, Email: user.Email})
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
