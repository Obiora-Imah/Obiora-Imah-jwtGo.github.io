package controllers

import (
	"JWTAPIGO/utils"
	"net/http"
)

func (c Controller) ProtectedEndPoint() http.HandlerFunc {
	return protectedEndPoint
}

func protectedEndPoint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	utils.ResponseJSON(w, "Authenticated request")
}
