package structs

import (
	"encoding/json"
	"errors"
)

var (
	ErrWrongPayload = errors.New("wrong payload")
)

type UserEntity struct {
	Email    *string `json:"email,omitempty"`
	Name     *string `json:"name,omitempty"`
	Password *string `json:"password,omitempty"`
	Salt     *string `json:"salt,omitempty"`
}

type UserGenericDTO struct {
	EmailJWT *string `json:"jwt,omitempty"`
	Password *string `json:"password,omitempty"`
}

type UserLoginDTO struct {
	Email    *string `json:"email,omitempty"`
	Password *string `json:"password,omitempty"`
}

func (user *UserEntity) Scan(src any) error {

	switch src.(type) {

	case []byte:
		err := json.Unmarshal(src.([]byte), &user)
		if err != nil {
			return err
		}

	case map[string]any:
		var ok bool
		user, ok = src.(*UserEntity)

		if !ok {
			return ErrWrongPayload
		}

	default:
		return ErrWrongPayload
	}

	return nil
}
