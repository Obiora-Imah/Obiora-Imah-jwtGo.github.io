package main

import (
	"JWTAPIGO/controllers"
	"JWTAPIGO/driver"
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/subosito/gotenv"
)

var db *sql.DB

func init() {
	gotenv.Load()
}

func main() {
	db = driver.ConnectDB()
	r := mux.NewRouter()
	controller := controllers.Controller{}
	r.HandleFunc("/signup", controller.Signup(db)).Methods("POST")
	r.HandleFunc("/login", controller.Login(db)).Methods("POST")
	r.HandleFunc("/protected", controller.TokeVerifierMiddleWare(controller.ProtectedEndPoint())).Methods("GET")
	log.Println("listening on port 7000")
	log.Fatal(http.ListenAndServe(":7000", r))
}
