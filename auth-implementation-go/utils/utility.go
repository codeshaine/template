package utils

import (
	"database/sql"
	"log"
	"login/structs"
	"os"
)

func CreateUserFolder(config *structs.Config, userID string) error {

	var retryCount = 0

retry:

	err := os.MkdirAll((config.WorkDir + "/" + userID), os.ModeDir)
	if err != nil {
		log.Default().Print(err.Error())
		if retryCount == 20 {
			return err
		}

		retryCount++
		goto retry
	}

	err = os.MkdirAll((config.WorkDir + "/" + userID + "/" + ".ssh"), os.ModeDir)
	if err != nil {
		log.Default().Print(err.Error())
		if retryCount == 20 {
			return err
		}

		retryCount++
		goto retry
	}

	return nil
}

func IsAllowed(postgres *sql.DB, config *structs.Config) (bool, error) {

	if config.Limit != 0 {
		rows, err := postgres.Query(`
			SELECT COUNT(*) FROM users
		`)

		if err != nil {
			return false, err
		}

		defer rows.Close()

		var count int64

		if rows.Next() {
			err = rows.Scan(&count)
			if err != nil {
				return false, err
			}

			if (count - 1) < int64(config.Limit) {
				return true, nil
			} else {
				return false, nil
			}
		} else {
			return false, nil
		}
	}

	return true, nil
}
