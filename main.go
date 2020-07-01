package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// postgresql://localhost:5432/fundthrough_stage

type User struct {
	ID       int    `json:"id"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

var db *sql.DB

func main() {
	// pq.ParseURL(os.Getenv("DATABASE_URL"))
	pgUrl, err := pq.ParseURL("postgresql://localhost:5432/jwt_go?sslmode=disable")
	checkError(err)
	db, err = sql.Open("postgres", pgUrl)
	checkError(err)
	err = db.Ping()
	checkError(err)
	r := mux.NewRouter()

	r.HandleFunc("/signup", signup).Methods("POST")
	r.HandleFunc("/login", login).Methods("POST")
	r.HandleFunc("/protected", tokeVerifierMiddleWare(protectedEndPoint)).Methods("GET")
	log.Println("listening on port 7000")
	log.Fatal(http.ListenAndServe(":7000", r))
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user User

	json.NewDecoder(r.Body).Decode(&user)
	if user.Email == "" {
		respondError("Email is missing", w, http.StatusBadRequest)
		return
	}

	if user.Password == "" {
		respondError("Password is missing", w, http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 20)
	checkError(err)
	user.Password = string(hash)
	stmt := "insert into users(email, password) values($1, $2) returning id;"
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)
	if err != nil {
		respondError("could not create user", w, http.StatusInternalServerError)
		return
	}
	user.Password = ""
	responseJSON(w, user)
}

func login(w http.ResponseWriter, r *http.Request) {
	var user User
	var jwt JWT
	json.NewDecoder(r.Body).Decode(&user)
	if user.Email == "" {
		respondError("Email is missing", w, http.StatusBadRequest)
		return
	}

	if user.Password == "" {
		respondError("Password is missing", w, http.StatusBadRequest)
		return
	}
	password := user.Password
	rows := db.QueryRow("select * from users where email = $1;", user.Email)
	err := rows.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		respondError("Wrong Email or Password", w, http.StatusBadRequest)
		return
	}
	hashedPassword := user.Password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	fmt.Println(err)
	if err != nil {
		respondError("Wrong Password", w, http.StatusBadRequest)
		return
	}
	token, err := generateToken(user)
	checkError(err)
	w.WriteHeader(http.StatusOK)
	jwt.Token = token
	responseJSON(w, jwt)
}

func protectedEndPoint(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Authenticated request"))
}

func tokeVerifierMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) == 2 {
			authToken := bearerToken[1]
			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte("secret"), nil
			})
			if error != nil {
				respondError(error.Error(), w, http.StatusBadRequest)
				return
			}
			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				respondError(error.Error(), w, http.StatusBadRequest)
				return
			}
			spew.Dump(token)
		} else {
			respondError("Invalid token", w, http.StatusUnauthorized)
			return
		}
		fmt.Println(bearerToken)
	})
}

func checkError(err interface{}) {
	if err != nil {
		log.Fatal(err)
	}
}

func responseJSON(w http.ResponseWriter, data interface{}) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)

}

func respondError(msg string, w http.ResponseWriter, status int) {
	var error Error
	error.Message = msg
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

func generateToken(user User) (string, error) {
	// var error Error
	secret := "secret"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})

	tokenString, err := token.SignedString([]byte(secret))
	checkError(err)
	// spew.Dump(token)

	return tokenString, nil
}
