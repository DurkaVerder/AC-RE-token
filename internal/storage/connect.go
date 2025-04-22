package storage

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

func Connect(driver, dns string) *sql.DB {
	db, err := sql.Open(driver, dns)
	if err != nil {
		panic(fmt.Sprintf("failed to connect to database: %v", err))
	}
	if err := db.Ping(); err != nil {
		panic(fmt.Sprintf("failed to ping database: %v", err))
	}
	return db
}
