package auth

import (
	"fmt"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	*gorm.Model
	ID          int
	Login       string
	DisplayName string
	Email       string
	Password    string
	Role        string
	Deactivated bool
}

type Session struct {
	*gorm.Model
	ID           string
	UserID       int
	RefreshToken string
	GivenToIp    string
}

func (session *Session) BeforeCreate(tx *gorm.DB) error {
	session.ID = fmt.Sprint("user", session.UserID, "_", uuid.New().String())
	return nil
}

type authDatabase struct {
	conn *gorm.DB
}

func newAuthDatabase(conn *gorm.DB) (*authDatabase, error) {
	instance := &authDatabase{conn: conn}
	err := instance.init()
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (db *authDatabase) init() error {
	err := db.conn.AutoMigrate(&User{})
	if err != nil {
		return err
	}

	err = db.conn.AutoMigrate(&Session{})
	if err != nil {
		return err
	}
	return nil
}

func (db *authDatabase) GetUserById(userId int) (*User, error) {
	var user User

	err := db.conn.First(&user, "id = ?", userId).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (db *authDatabase) GetUserByLogin(login string) (*User, error) {
	var user User

	err := db.conn.First(&user, "login = ?", login).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (db *authDatabase) GetUserByEmail(email string) (*User, error) {
	var user User
	err := db.conn.First(&user, "email = ?", email).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (db *authDatabase) AddUser(user *User) error {
	return db.conn.Create(&user).Error
}

func (db *authDatabase) UpdateUser(user *User) error {
	return db.conn.Save(&user).Error
}

func (db *authDatabase) GetSessionByRefreshToken(refreshToken string) (*Session, error) {
	var session Session
	err := db.conn.First(&session, "refresh_token = ?", refreshToken).Error
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (db *authDatabase) AddSession(session *Session) error {
	return db.conn.Create(&session).Error
}

func (db *authDatabase) UpdateSession(session *Session) error {
	return db.conn.Save(&session).Error
}

func (db *authDatabase) RemoveSession(session *Session) {
	db.conn.Delete(session)
}
