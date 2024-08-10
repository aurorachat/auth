package utils

import (
	"encoding/base64"
	"fmt"
	rand2 "math/rand"
	"regexp"
	"time"
)

const defaultTokenCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func IsEmailValid(e string) bool {
	emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return emailRegex.MatchString(e)
}

func IsLoginValid(login string) bool {
	loginRegex := regexp.MustCompile(`^[a-z0-9-_]{3,11}$`)
	return loginRegex.MatchString(login)
}

func GenerateOpaqueToken(userId int) string {
	tokenPrefix := base64.StdEncoding.EncodeToString([]byte(fmt.Sprint(userId, time.Now().String())))
	return tokenPrefix + "___" + generateRandomString(defaultTokenCharset, 32)
}

func generateRandomString(charset string, length int) string {
	b := make([]byte, length)
	var seededRand *rand2.Rand = rand2.New(rand2.NewSource(time.Now().UnixNano()))
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}
