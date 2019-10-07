package client

import (
	"net/http"
)

// Error 带有错误码的 error
type Error struct {
	Code    int
	Message string
}

func (err *Error) Error() string {
	return err.Message
}

var (
	// ErrUserNotFound 用户不存在
	ErrUserNotFound = &Error{Code: http.StatusUnauthorized, Message: "user isn't found"}

	// ErrPasswordNotMatch 密码不正确
	ErrPasswordNotMatch = &Error{Code: http.StatusUnauthorized, Message: "password isn't match"}

	// ErrTicketNotFound Ticket 没有找到
	ErrTicketNotFound = &Error{Code: http.StatusUnauthorized, Message: "ticket isn't found"}
)
