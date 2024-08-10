package auth

import (
	"github.com/aurorachat/jwt-tokens/tokens"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"net/http"
)

const (
	ActionAuth = iota
	ActionRegister
)

type AuthUser struct {
	*gorm.Model
	ID       int
	Login    string
	Email    string
	Password string
}

type AuthDto struct {
	Login    string
	Email    string
	Password string
}

type AuthActionContext struct {
	User       *AuthUser
	ActionType int
	cancelled  bool
}

func (authCtx *AuthActionContext) Cancelled() bool {
	return authCtx.cancelled
}

func (authCtx *AuthActionContext) Cancel() {
	authCtx.cancelled = true
}

type Handler func(ctx *AuthActionContext)

type Options struct {
	Handler     Handler
	Database    *gorm.DB
	Server      *gin.Engine
	SecretToken []byte
}

type AuthResponseWrapper struct {
	Error *string
	Data  interface{}
}

func NewOptions(handler Handler, database *gorm.DB, server *gin.Engine, secretToken []byte) *Options {
	return &Options{
		Handler:     handler,
		Database:    database,
		Server:      server,
		SecretToken: secretToken,
	}
}

func Initialize(options *Options) error {
	tokens.SetSecretToken(options.SecretToken)

	err := options.Database.AutoMigrate(&AuthUser{})
	if err != nil {
		return err
	}

	options.Server.POST("/users/register", func(c *gin.Context) {
		var user AuthDto
		err := c.BindJSON(&user)
		if err != nil {
			errMsg := err.Error()
			c.JSON(http.StatusBadRequest, AuthResponseWrapper{
				Error: &errMsg,
				Data:  nil,
			})
			return
		}
		authUserModel := &AuthUser{
			Login:    user.Login,
			Email:    user.Email,
			Password: user.Password,
		}
		ctx := &AuthActionContext{
			User:       authUserModel,
			ActionType: ActionRegister,
			cancelled:  false,
		}
		existing := &AuthUser{}
		err = options.Database.First(&existing, "login = ?", authUserModel.Login).Error
		if err == nil {
			errMsg := "user with that login already exists"
			c.JSON(http.StatusBadRequest, AuthResponseWrapper{
				Error: &errMsg,
				Data:  nil,
			})
			return
		}

		options.Handler(ctx)
		if ctx.cancelled {
			errMsg := "your registration request has been cancelled"
			c.JSON(http.StatusBadRequest, AuthResponseWrapper{
				Error: &errMsg,
				Data:  nil,
			})
			return
		}

		options.Database.Save(authUserModel)
		c.JSON(http.StatusOK, AuthResponseWrapper{
			Error: nil,
			Data:  authUserModel.ID,
		})
	})
	return nil
}
