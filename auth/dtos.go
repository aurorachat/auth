package auth

type RegisterDto struct {
	Login       string
	DisplayName string
	Email       string
	Password    string
}

type AuthDto struct {
	Login    string
	Password string
}
