package users

import (
	"net/http"

	"github.com/labstack/echo"
)

var (
	// ErrUsernameEmpty 用户名为空
	ErrUsernameEmpty = echo.NewHTTPError(http.StatusUnauthorized, "user name is empty")

	// ErrPasswordEmpty 密码为空
	ErrPasswordEmpty = echo.NewHTTPError(http.StatusUnauthorized, "user password is empty")

	// ErrUserNotFound 用户未找到
	ErrUserNotFound = echo.NewHTTPError(http.StatusUnauthorized, "user isn't found")

	// ErrPasswordNotMatch 密码不正确
	ErrPasswordNotMatch = echo.NewHTTPError(http.StatusUnauthorized, "password isn't match")

	// ErrMutiUsers 找到多个用户
	ErrMutiUsers = echo.NewHTTPError(http.StatusUnauthorized, "muti users is found")

	// ErrUserLocked 用户已被锁定
	ErrUserLocked = echo.NewHTTPError(http.StatusUnauthorized, "user is locked")

	// ErrUserIPBlocked 用户不在指定的 IP 范围登录
	ErrUserIPBlocked = echo.NewHTTPError(http.StatusUnauthorized, "user address is blocked")

	// ErrServiceTicketNotFound Service ticket 没有找到
	ErrServiceTicketNotFound = echo.NewHTTPError(http.StatusUnauthorized, "service ticket isn't found")

	// ErrServiceTicketExpired Service ticket 已过期
	ErrServiceTicketExpired = echo.NewHTTPError(http.StatusUnauthorized, "service ticket isn't expired")

	// ErrUnauthorizedService Service 是未授权的
	ErrUnauthorizedService = echo.NewHTTPError(http.StatusUnauthorized, "service is unauthorized")

	// ErrUserAlreadyOnline 用户已登录
	ErrUserAlreadyOnline = echo.NewHTTPError(http.StatusUnauthorized, "user is already online")

	// ErrPermissionDenied 没有权限
	ErrPermissionDenied = echo.NewHTTPError(http.StatusUnauthorized, "permission is denied")

	// ErrCaptchaKey
	ErrCaptchaKey = echo.NewHTTPError(http.StatusUnauthorized, "captcha is error")

	// ErrCaptchaMissing
	ErrCaptchaMissing = echo.NewHTTPError(http.StatusUnauthorized, "captcha is missing")
)

type ErrOnline struct {
	onlineList []SessionInfo
}

func (err *ErrOnline) Error() string {
	if len(err.onlineList) == 1 {
		return "用户已在 " + err.onlineList[0].Address +
			" 上登录，最后一次活动时间为 " +
			err.onlineList[0].UpdatedAt.Format("2006-01-02 15:04:05Z07:00")

	}
	return "用户已在其他机器上登录"
}

func IsOnlinedError(err error) ([]SessionInfo, bool) {
	oe, ok := err.(*ErrOnline)
	if ok {
		return oe.onlineList, true
	}
	return nil, false
}

type ErrExternalServer struct {
	Msg string
}

func (e *ErrExternalServer) Error() string {
	return e.Msg
}

func IsErrExternalServer(e error) bool {
	_, ok := e.(*ErrExternalServer)
	return ok
}
