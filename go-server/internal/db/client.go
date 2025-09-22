package db

import (
	"database/sql"
	"log"
	"time"
)

func GetDBInstace(destination string) (*sql.DB, error) {

	var retry = 0

sqlRetry:
	sqlClient, err := sql.Open("postgres", destination)
	if err != nil {
		if retry == 50 {
			log.Default().Fatalf("Error: %s\n", err.Error())
		}

		retry++
		time.Sleep(time.Minute)
		goto sqlRetry
	}

	return sqlClient, nil
}
