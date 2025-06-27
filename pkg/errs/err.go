package errs

import "errors"

var (
	ErrInvalidToken   = errors.New("invalid token, no related account exists")
	ErrQueryUserInfo  = errors.New("query user info fail")
	ErrUpdateUserInfo = errors.New("update user info fail")
	ErrGenerateToken  = errors.New("generate token fail")
)

func ParmaNeedErr(name string) error {
	return errors.New(name + " needs to be provided")
}
