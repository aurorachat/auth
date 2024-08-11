package auth

import (
	"fmt"
	"github.com/aurorachat/jwt-tokens/tokens"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"net/http"
)

const (
	ActionAuth = iota
	ActionRegister
	ActionRefreshToken
)

type ActionContext struct {
	// ActionPayload Can be either RegisterDto or AuthDto
	ActionPayload interface{}
	// ActionType Can be either ActionAuth or ActionRegister
	ActionType   int
	cancelled    bool
	cancelReason string
}

func (authCtx *ActionContext) Cancelled() bool {
	return authCtx.cancelled
}

func (authCtx *ActionContext) Cancel() {
	authCtx.CancelWithReason("request has been cancelled")
}

func (authCtx *ActionContext) CancelWithReason(reason string) {
	authCtx.cancelled = true
	authCtx.cancelReason = reason
}

type Handler func(ctx *ActionContext)

type Options struct {
	Handler     Handler
	Database    *gorm.DB
	Server      *gin.Engine
	SecretToken []byte
}

type ResponseWrapper struct {
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

type Engine struct {
	options      *Options
	authDatabase *authDatabase
}

func NewEngine(options *Options) (*Engine, error) {
	instance := &Engine{options: options}
	err := instance.initialize()
	return instance, err
}

func (e *Engine) initialize() error {
	tokens.SetSecretToken(e.options.SecretToken)
	db, err := newAuthDatabase(e.options.Database)

	if err != nil {
		return err
	}

	e.authDatabase = db

	service := newAuthService(db, e.options.Handler)

	e.options.Server.POST("/auth/register", func(c *gin.Context) {
		var user RegisterDto
		err := c.BindJSON(&user)
		if err != nil {
			respondFail(c, http.StatusBadRequest, fmt.Sprintf("payload is incorrect: %s", err.Error()))
			return
		}

		err = service.RegisterUser(user.Email, user.Login, user.Password)

		if err != nil {
			respondFail(c, http.StatusBadRequest, err.Error())
			return
		}

		respondSuccess(c, http.StatusOK, nil)
	})
	e.options.Server.POST("/auth/login", func(c *gin.Context) {
		var user AuthDto

		err := c.BindJSON(&user)
		if err != nil {
			respondFail(c, http.StatusBadRequest, fmt.Sprintf("payload is incorrect: %s", err.Error()))
			return
		}

		accessToken, refreshToken, err := service.AuthenticateUser(c.RemoteIP(), user.Login, user.Password)

		if err != nil {
			respondFail(c, http.StatusBadRequest, err.Error())
			return
		}

		respondSuccess(c, http.StatusOK, gin.H{
			"accessToken":  accessToken,
			"refreshToken": refreshToken,
		})
	})
	e.options.Server.POST("/auth/refresh", func(c *gin.Context) {
		var inputRefresh string
		err := c.Bind(&inputRefresh)
		if err != nil {
			respondFail(c, http.StatusBadRequest, fmt.Sprintf("payload is incorrect: %s", err.Error()))
		}

		accessToken, refreshToken, err := service.RefreshAuthToken(inputRefresh)
		if err != nil {
			respondFail(c, http.StatusBadRequest, err.Error())
			return
		}

		respondSuccess(c, http.StatusOK, gin.H{
			"accessToken":  accessToken,
			"refreshToken": refreshToken,
		})
	})
	return nil
}

func (e *Engine) SetUserActivated(userId int, status bool) error {
	user, err := e.authDatabase.GetUserById(userId)

	if err != nil {
		return err
	}

	user.Deactivated = !status
	return e.authDatabase.UpdateUser(user)
}

func (e *Engine) SetUserRole(userId int, newRole string) error {
	user, err := e.authDatabase.GetUserById(userId)

	if err != nil {
		return err
	}

	user.Role = newRole
	return e.authDatabase.UpdateUser(user)
}

func respondSuccess(ctx *gin.Context, statusCode int, data interface{}) {
	ctx.JSON(statusCode, ResponseWrapper{Error: nil, Data: data})
}

func respondFail(ctx *gin.Context, statusCode int, err string) {
	ctx.JSON(statusCode, ResponseWrapper{Error: &err, Data: nil})
}
