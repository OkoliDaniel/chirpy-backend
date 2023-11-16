package main

import (
	"log"
	"net/http"
	"os"

	"internal/database"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
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
	DB             *database.DB
	jwtSecret      string
	polkaApiKey    string
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
	corsMux := middlewareCors(mux)
	cfgPtr := &apiConfig{
		fileserverHits: 0,
		DB:             db,
		jwtSecret:      jwtSecret,
		polkaApiKey:    polkaAPiKey,
	}
	fsHandler := cfgPtr.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	mux.Handle("/app/*", fsHandler)
	mux.Handle("/app", fsHandler)
	mux.Handle("/app/assets", http.StripPrefix("/app", http.FileServer(http.Dir("."))))
	adminMux.Get("/metrics", cfgPtr.sendFileServerHits)
	apiMux.HandleFunc("/reset", cfgPtr.resetFileServerHits)
	apiMux.Get("/healthz", cfgPtr.handlerReadiness)
	apiMux.Post("/chirps", cfgPtr.handlerCreateChirp)
	apiMux.Get("/chirps", cfgPtr.handlerGetChirps)
	apiMux.Get("/chirps/{chirpID}", cfgPtr.handlerGetChirp)
	apiMux.Delete("/chirps/{chirpID}", cfgPtr.handlerDeleteChirp)
	apiMux.Post("/users", cfgPtr.handlerCreateUser)
	apiMux.Post("/login", cfgPtr.handlerLogin)
	apiMux.Put("/users", cfgPtr.handlerUpdateUser)
	apiMux.Post("/polka/webhooks", cfgPtr.handlerWebhook)
	apiMux.Post("/refresh", cfgPtr.handlerRefresh)
	apiMux.Post("/revoke", cfgPtr.handlerRevoke)

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
