package auth

import (
	"database/sql"
	"errors"
	"github.com/aurorachat/auth/utils"
	"github.com/aurorachat/jwt-tokens/tokens"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type authService struct {
	db *authDatabase
}

func newAuthService(db *authDatabase) *authService {
	return &authService{db}
}

func (s *authService) DB() *authDatabase {
	return s.db
}

func (s *authService) RegisterUser(email, login, password string) error {
	if !utils.IsEmailValid(email) {
		return errors.New("invalid email")
	}

	if !utils.IsLoginValid(login) {
		return errors.New("invalid login")
	}

	_, err := s.db.GetUserByLogin(login)

	if err == nil {
		return errors.New("user with this login exists")
	}

	if len(password) < 3 {
		return errors.New("password is too short")
	}

	encryptedPwd, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		return err
	}

	userModel := &User{
		Email:    email,
		Login:    login,
		Password: string(encryptedPwd),
	}

	err = s.db.AddUser(userModel)
	if err != nil {
		return err
	}
	return nil
}

func (s *authService) AuthenticateUser(remoteIp string, loginOrEmail string, rawPassword string) (string, *Session, error) {
	user, err := s.db.GetUserByLogin(loginOrEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			user, err = s.db.GetUserByEmail(loginOrEmail)

			if err != nil {
				return "", nil, errors.New("user not found")
			}
		}
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(rawPassword)) != nil {
		return "", nil, errors.New("invalid password")
	}

	session := &Session{
		UserID:       user.ID,
		RefreshToken: utils.GenerateOpaqueToken(user.ID),
		GivenToIp:    remoteIp,
	}
	err = s.db.AddSession(session)
	if err != nil {
		return "", nil, err
	}
	createdJwt, err := tokens.CreateJWT(jwt.MapClaims{
		"sub": user.ID,
		"iss": "github.com/aurorachat/auth",
		"exp": time.Now().Add(time.Minute * 30).Unix(),
		"iat": time.Now().Add(time.Hour).Unix(),
	})

	return createdJwt, session, nil
}

func (s *authService) RefreshAuthToken(refreshToken string) (string, string, error) {
	session, err := s.db.GetSessionByRefreshToken(refreshToken)
	if err != nil {
		return "", "", err
	}
	session.RefreshToken = utils.GenerateOpaqueToken(session.UserID)
	err = s.db.UpdateSession(session)
	if err != nil {
		return "", "", err
	}
	createdJwt, err := tokens.CreateJWT(jwt.MapClaims{
		"sub": session.UserID,
		"iss": "github.com/aurorachat/auth",
		"exp": time.Now().Add(time.Minute * 30).Unix(),
		"iat": time.Now().Add(time.Hour).Unix(),
	})
	return createdJwt, session.RefreshToken, err
}
