package main

import (
	"fmt"
	"github.com/aurorachat/auth/auth"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	dsn := "host=localhost user=aurorachat password=123456 dbname=aurorachat port=5432 sslmode=disable TimeZone=Asia/Tbilisi"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	e := gin.Default()
	authE, err := auth.NewEngine(auth.NewOptions(func(ctx *auth.ActionContext) {
		fmt.Println("OH WOW! New user is being!")
	}, db, e, []byte("gagwaughawuta")))
	if err != nil {
		panic(err)
	}
	err = authE.SetUserActivated(1, false)
	if err != nil {
		panic(err)
	}
	e.GET("/pong", auth.Authorization(), func(context *gin.Context) {
		context.JSON(200, gin.H{
			"message": "pong",
		})
	})
	if err != nil {
		panic(err)
	}
	err = e.Run(":8080")
	if err != nil {
		panic(err)
	}
}
