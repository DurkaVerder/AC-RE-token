package store

import "database/sql"

type Postgres struct {
	db *sql.DB
}
