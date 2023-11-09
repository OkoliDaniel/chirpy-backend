module github.com/OkoliDaniel/chirpy-backend

go 1.21.2

replace internal/database v0.0.0 => ./internal/database

require (
	github.com/go-chi/chi/v5 v5.0.10
	github.com/joho/godotenv v1.5.1
	golang.org/x/crypto v0.14.0
	internal/database v0.0.0
	github.com/golang-jwt/jwt/v5 v5.1.0
)
