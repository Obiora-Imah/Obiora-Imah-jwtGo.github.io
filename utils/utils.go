package utils

import (
	"JWTAPIGO/models"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

func CheckError(err interface{}) {
	if err != nil {
		log.Fatal(err)
	}
}

func ResponseJSON(w http.ResponseWriter, data interface{}) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)

}

func RespondError(msg string, w http.ResponseWriter, status int) {
	var error models.Error
	fmt.Println(msg)
	error.Message = msg
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(error)
}

func GenerateToken(user models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	CheckError(err)
	// spew.Dump(token)

	return tokenString, nil
}

func ComparePasswords(hashedPassword string, password string, w http.ResponseWriter) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return err
	}
	return nil
}
