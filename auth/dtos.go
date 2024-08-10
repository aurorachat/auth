package auth

type RegisterDto struct {
	Login    string
	Email    string
	Password string
}

type AuthDto struct {
	Login    string
	Password string
}
