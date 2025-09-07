package login

import "context"

type UserLogin interface {
	LoginUser(ctx context.Context, email string, password string) (uuid int64, err error)
}
