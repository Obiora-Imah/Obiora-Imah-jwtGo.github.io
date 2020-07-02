package controllers

import (
	"JWTAPIGO/utils"
	"net/http"
)

func ProtectedEndPoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	utils.ResponseJSON(w, "Authenticated request")
}
