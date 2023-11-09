package database

import (
	"encoding/json"
	"os"
	"sync"
)

type DB struct {
	path string
	mux  *sync.RWMutex
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Chirp struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
}

func (db *DB) ensureDB() error {
	// ensureDB creates a new database file if it doesn't exist
	defer db.mux.Unlock()
	db.mux.Lock()
	_, err := os.ReadFile(db.path)
	if !os.IsNotExist(err) {
		return nil
	}
	data, err := json.Marshal(DBStructure{
		Chirps: make(map[int]Chirp),
		Users:  make(map[int]User),
	})
	if err != nil {
		return err
	}
	err = os.WriteFile(db.path, data, 0666)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) loadDB() (DBStructure, error) {
	// loadDB reads the database file into memory
	defer db.mux.RUnlock()
	err := db.ensureDB()
	if err != nil {
		return DBStructure{}, err
	}
	db.mux.RLock()
	file, err := os.ReadFile(db.path)
	if err != nil {
		return DBStructure{}, err
	}
	dbStruct := DBStructure{}
	err = json.Unmarshal(file, &dbStruct)
	if err != nil {
		return DBStructure{}, err
	}
	return dbStruct, nil
}

func (db *DB) writeDB(dbStructure DBStructure) error {
	// writeDB writes the database file to disk
	defer db.mux.Unlock()
	db.mux.Lock()
	data, err := json.MarshalIndent(dbStructure, "", "	")
	if err != nil {
		return err
	}
	err = os.WriteFile(db.path, data, 0666)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) GetChirps() ([]Chirp, error) {
	// GetChirps returns all chirps in the database
	dbStruct, err := db.loadDB()
	if err != nil {
		return nil, err
	}
	chirpsMap := dbStruct.Chirps
	chirps := make([]Chirp, len(chirpsMap))
	for key, chirp := range chirpsMap {
		chirps[key-1] = chirp
	}
	return chirps, nil
}

func (db *DB) GetChirp(id int) (Chirp, error) {
	// GetChirp returns the chirp with `id` from the database if it exists
	dbStruct, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}
	chirp, ok := dbStruct.Chirps[id]
	if !ok {
		return Chirp{}, nil
	}
	return chirp, nil
}

func (db *DB) CreateChirp(body string) (Chirp, error) {
	// CreateChirp creates a new chirp and saves it to disk
	dbStruct, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}
	chirpID := len(dbStruct.Chirps) + 1
	chirp := Chirp{
		ID:   chirpID,
		Body: body,
	}
	dbStruct.Chirps[chirpID] = chirp
	err = db.writeDB(dbStruct)
	if err != nil {
		return Chirp{}, err
	}
	return chirp, nil
}

func (db *DB) CreateUser(email, password string) (User, error) {
	// CreateUser creates a new user and saves it to disk
	dbStruct, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	for _, user := range dbStruct.Users {
		if user.Email == email {
			return User{}, nil
		}
	}
	userID := len(dbStruct.Users) + 1
	user := User{
		ID:       userID,
		Email:    email,
		Password: password,
	}
	dbStruct.Users[userID] = user
	err = db.writeDB(dbStruct)
	if err != nil {
		return User{}, err
	}
	return user, nil
}

func (db *DB) GetUser(email string) (User, error) {
	// GetUser returns the user with `email` from thr database if it exists
	dbStruct, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	users := dbStruct.Users
	for _, user := range users {
		if user.Email == email {
			return user, nil
		}
	}
	return User{}, nil
}

func (db *DB) UpdateUser(id int, email, password string) (User, error) {
	// UpdateUser updates a user's email and password, if the user exsts, and saves it to disk
	dbStruct, err := db.loadDB()
	if err != nil {
		return User{}, err
	}
	userData, ok := dbStruct.Users[id]
	if !ok {
		return User{}, nil
	}
	userData.Email = email
	userData.Password = password
	dbStruct.Users[id] = userData
	err = db.writeDB(dbStruct)
	if err != nil {
		return User{}, err
	}
	return userData, nil
}

func NewDB(path string) (*DB, error) {
	/* NewDB creates a new database connection
	   and creates the database file if it doesn't exist*/
	db := DB{
		path: path,
		mux:  &sync.RWMutex{},
	}
	_, err := os.ReadFile(path)
	if !os.IsNotExist(err) {
		return &db, nil
	}
	data, err := json.Marshal(DBStructure{
		Chirps: make(map[int]Chirp),
		Users:  make(map[int]User),
	})
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(path, data, 0666)
	if err != nil {
		return nil, err
	}
	return &db, nil
}
