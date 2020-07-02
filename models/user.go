package models

type User struct {
	ID       int    `json:"id"`
	Password string `json:"password"`
	Email    string `json:"email"`
}
