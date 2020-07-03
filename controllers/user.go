package controllers

import (
	"JWTAPIGO/models"
	userRepository "JWTAPIGO/repository/user"
	"JWTAPIGO/utils"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type Controller struct{}

var db *sql.DB

func (c Controller) Signup(_db *sql.DB) http.HandlerFunc {
	db = _db
	return signup
}

func (c Controller) Login(_db *sql.DB) http.HandlerFunc {
	db = _db
	return login
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user models.User
	w.Header().Set("Content-Type", "application/json")
	json.NewDecoder(r.Body).Decode(&user)
	if user.Email == "" {
		utils.RespondError("Email is missing", w, http.StatusBadRequest)
		return
	}

	if user.Password == "" {
		utils.RespondError("Password is missing", w, http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		utils.RespondError("An error has occured", w, http.StatusInternalServerError)
		return
	}
	user.Password = string(hash)
	userRepo := userRepository.UserRepository{}
	user = userRepo.Signup(db, user)

	if err != nil {
		msg := fmt.Sprint(err)
		utils.RespondError(msg, w, http.StatusInternalServerError)
		return
	}
	user.Password = ""
	utils.ResponseJSON(w, user)
}

func login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	var jwt models.JWT
	w.Header().Set("Content-Type", "application/json")
	json.NewDecoder(r.Body).Decode(&user)
	if user.Email == "" {
		utils.RespondError("Email is missing", w, http.StatusBadRequest)
		return
	}

	if user.Password == "" {
		utils.RespondError("Password is missing", w, http.StatusBadRequest)
		return
	}
	password := user.Password
	userRepo := userRepository.UserRepository{}
	user, err := userRepo.Login(db, user)
	if err != nil {
		utils.RespondError("Wrong Email or Password", w, http.StatusBadRequest)
		return
	}
	hashedPassword := user.Password
	error := utils.ComparePasswords(hashedPassword, password, w)
	if error != nil {
		utils.RespondError("Wrong Password", w, http.StatusBadRequest)
		return
	}
	token, err := utils.GenerateToken(user)
	utils.CheckError(err)
	jwt.Token = token
	utils.ResponseJSON(w, jwt)
}

func (c Controller) TokeVerifierMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) == 2 {
			authToken := bearerToken[1]
			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}
				return []byte(os.Getenv("SECRET")), nil
			})
			if error != nil {
				utils.RespondError(error.Error(), w, http.StatusBadRequest)
				return
			}
			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				utils.RespondError(error.Error(), w, http.StatusBadRequest)
				return
			}
			spew.Dump(token)
		} else {
			utils.RespondError("Invalid token", w, http.StatusUnauthorized)
			return
		}
		fmt.Println(bearerToken)
	})
}
