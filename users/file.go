package users

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var _ UserManager = &FileUserManager{}

type FileUserManager struct {
	Logger        *log.Logger
	RootDir       string
	SigningMethod SigningMethod
}

func (h *FileUserManager) Unlock(username string) error {
	return nil
}

func (h *FileUserManager) Lock(username string) error {
	return nil
}

func (h *FileUserManager) Locked() ([]LockedUser, error) {
	return nil, nil
}

func (h *FileUserManager) Read(loginInfo *LoginInfo) (Authentication, error) {
	file := filepath.Join(h.RootDir, "nflow_users.json")
	reader, err := os.Open(file)
	if err != nil {
		if os.IsNotExist(err) {
			h.Logger.Println("[warn]", err)

			if "admin" == loginInfo.Username {
				return &fileUser{name: "admin",
					password:      "admin",
					data:          map[string]interface{}{"username": "admin", "password": "admin"},
					signingMethod: h.SigningMethod}, nil
			}
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	defer reader.Close()

	var users []map[string]interface{}
	if err := json.NewDecoder(reader).Decode(&users); err != nil {
		return nil, err
	}

	for _, user := range users {
		name := fmt.Sprint(user["username"])
		if name == loginInfo.Username {
			password := fmt.Sprint(user["password"])
			return &fileUser{name: name,
				password:      password,
				data:          user,
				signingMethod: h.SigningMethod}, nil
		}
	}
	return nil, nil
}

func (ah *FileUserManager) FailCount(username string) int {
	return 0
}

func (ow *FileUserManager) Auth(auth Authentication, loginInfo *LoginInfo) (*UserInfo, error) {
	return auth.Auth(loginInfo)
}

type fileUser struct {
	name          string
	password      string
	data          map[string]interface{}
	signingMethod SigningMethod
}

func (u *fileUser) ID() interface{} {
	return u.name
}

func (u *fileUser) Name() string {
	return u.name
}

func (u *fileUser) Password() string {
	return u.password
}

func (u *fileUser) IsValid(addr string) (bool, error) {
	return true, nil
}

func (u *fileUser) Data() map[string]interface{} {
	return u.data
}

func (u *fileUser) Auth(loginInfo *LoginInfo) (*UserInfo, error) {
	err := u.signingMethod.Verify(loginInfo.Password, u.password, "")
	if err != nil {
		return nil, err
	}
	return &UserInfo{
		LoginInfo: *loginInfo,
		ID:        u.ID(),
		Data:      u.Data(),
	}, nil
}
