package auth

import (
	"errors"
	"github.com/aurorachat/auth/utils"
	"github.com/aurorachat/jwt-tokens/tokens"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"time"
)

type authService struct {
	db      *authDatabase
	handler Handler
}

func newAuthService(db *authDatabase, handler Handler) *authService {
	return &authService{db, handler}
}

func (s *authService) DB() *authDatabase {
	return s.db
}

func (s *authService) RegisterUser(email, login, displayName, password string) error {
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
		Email:       email,
		Login:       login,
		Password:    string(encryptedPwd),
		Role:        "User",
		DisplayName: displayName,
	}

	ctx := &ActionContext{
		ActionPayload: userModel,
		ActionType:    ActionRegister,
		cancelled:     false,
		cancelReason:  "",
	}

	s.handler(ctx)

	if ctx.cancelled {
		return errors.New(ctx.cancelReason)
	}

	err = s.db.AddUser(userModel)
	if err != nil {
		return err
	}
	return nil
}

func (s *authService) AuthenticateUser(remoteIp string, loginOrEmail string, rawPassword string) (string, string, error) {
	user, err := s.db.GetUserByLogin(loginOrEmail)
	if err != nil {
		user, err = s.db.GetUserByEmail(loginOrEmail)

		if err != nil {
			return "", "", errors.New("user not found")
		}
	}

	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(rawPassword)) != nil {
		return "", "", errors.New("invalid password")
	}

	if user.Deactivated {
		return "", "", errors.New("this account is deactivated")
	}

	session := &Session{
		UserID:       user.ID,
		RefreshToken: utils.GenerateOpaqueToken(user.ID),
		GivenToIp:    remoteIp,
	}

	ctx := &ActionContext{
		ActionPayload: session,
		ActionType:    ActionAuth,
		cancelled:     false,
		cancelReason:  "",
	}

	s.handler(ctx)

	if ctx.cancelled {
		return "", "", errors.New(ctx.cancelReason)
	}

	err = s.db.AddSession(session)
	if err != nil {
		return "", "", err
	}
	createdJwt, err := tokens.CreateJWT(jwt.MapClaims{
		"sub":         user.ID,
		"iss":         "github.com/aurorachat/auth",
		"exp":         time.Now().Add(time.Minute * 5).Unix(),
		"iat":         time.Now().Unix(),
		"role":        user.Role,
		"sessionId":   session.ID,
		"displayName": user.DisplayName,
	})

	return createdJwt, session.RefreshToken, nil
}

func (s *authService) RefreshAuthToken(refreshToken string) (string, string, error) {
	session, err := s.db.GetSessionByRefreshToken(refreshToken)
	if err != nil {
		return "", "", err
	}
	ctx := &ActionContext{
		ActionPayload: session,
		ActionType:    ActionRefreshToken,
		cancelled:     false,
		cancelReason:  "",
	}
	user, err := s.db.GetUserById(session.UserID)
	if err != nil {
		return "", "", err
	}
	if user.Deactivated {
		return "", "", errors.New("this account is deactivated")
	}
	s.handler(ctx)
	if ctx.cancelled {
		return "", "", errors.New(ctx.cancelReason)
	}
	session.RefreshToken = utils.GenerateOpaqueToken(session.UserID)
	err = s.db.UpdateSession(session)
	if err != nil {
		return "", "", err
	}
	createdJwt, err := tokens.CreateJWT(jwt.MapClaims{
		"sub":         user.ID,
		"iss":         "github.com/aurorachat/auth",
		"exp":         time.Now().Add(time.Minute * 5).Unix(),
		"iat":         time.Now().Unix(),
		"role":        user.Role,
		"sessionId":   session.ID,
		"displayName": user.DisplayName,
	})
	return createdJwt, session.RefreshToken, err
}
