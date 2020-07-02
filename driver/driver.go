package driver

import (
	"JWTAPIGO/utils"
	"database/sql"
	"os"

	"github.com/lib/pq"
)

var db *sql.DB

func ConnectDB() *sql.DB {
	pgUrl, err := pq.ParseURL(os.Getenv("DATABASE_URL"))
	utils.CheckError(err)
	db, err = sql.Open("postgres", pgUrl)
	utils.CheckError(err)
	err = db.Ping()
	utils.CheckError(err)
	return db
}
