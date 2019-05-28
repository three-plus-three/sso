package users

import "context"

type AuthResult struct {
	IsNewUser bool
	ID        interface{}
	Name      string
	Data      map[string]interface{}
}

type AuthFunc func(*AuthContext) error

type AuthContext struct {
	Context context.Context

	Username     string `json:"username" xml:"username" form:"username" query:"username"`
	Password     string `json:"password" xml:"password" form:"password" query:"password"`
	Service      string `json:"service" xml:"service" form:"service" query:"service"`
	ForceLogin   string `json:"force,omitempty" xml:"force" form:"force" query:"force"`
	CaptchaKey   string `json:"captcha_key,omitempty" xml:"captcha_key" form:"captcha_key" query:"captcha_key"`
	CaptchaValue string `json:"captcha_value,omitempty" xml:"captcha_value" form:"captcha_value" query:"captcha_value"`

	Address   string
	NoCaptcha bool

	Result AuthResult

	Authentication AuthFunc
}

func (u *AuthContext) IsForce() bool {
	return u.ForceLogin == "on" ||
		u.ForceLogin == "true" ||
		u.ForceLogin == "checked"
}

type AuthService struct {
	beforeLoadFuncs []AuthFunc
	loadFuncs       []func(*AuthContext) (bool, error)
	afterLoadFuncs  []AuthFunc
	beforeAuthFuncs []AuthFunc
	authFuncs       []AuthFunc
	afterAuthFuncs  []AuthFunc
	errFuncs        []func(ctx *AuthContext, err error) error
}

func (as *AuthService) OnBeforeLoad(cb AuthFunc) {
	as.beforeLoadFuncs = append(as.beforeLoadFuncs, cb)
}
func (as *AuthService) OnLoad(cb func(*AuthContext) (bool, error)) {
	as.loadFuncs = append(as.loadFuncs, cb)
}
func (as *AuthService) OnAfterLoad(cb AuthFunc) {
	as.afterLoadFuncs = append(as.afterLoadFuncs, cb)
}
func (as *AuthService) OnBeforeAuth(cb AuthFunc) {
	as.beforeAuthFuncs = append(as.beforeAuthFuncs, cb)
}
func (as *AuthService) OnAuth(cb AuthFunc) {
	as.authFuncs = append(as.authFuncs, cb)
}
func (as *AuthService) OnAfterAuth(cb AuthFunc) {
	as.afterAuthFuncs = append(as.afterAuthFuncs, cb)
}
func (as *AuthService) OnError(cb func(ctx *AuthContext, err error) error) {
	as.errFuncs = append(as.errFuncs, cb)
}

func (as *AuthService) Auth(ctx *AuthContext) error {
	for _, a := range as.beforeLoadFuncs {
		if err := a(ctx); err != nil {
			return as.callError(ctx, err)
		}
	}

	isLoaded := false
	for _, a := range as.loadFuncs {
		ok, err := a(ctx)
		if err != nil {
			return as.callError(ctx, err)
		}
		if ok {
			isLoaded = true
			break
		}
	}
	if !isLoaded {
		return as.callError(ctx, ErrUserNotFound)
	}
	for _, a := range as.afterLoadFuncs {
		if err := a(ctx); err != nil {
			return as.callError(ctx, err)
		}
	}
	for _, a := range as.beforeAuthFuncs {
		if err := a(ctx); err != nil {
			return as.callError(ctx, err)
		}
	}
	for _, a := range as.authFuncs {
		if err := a(ctx); err != nil {
			return as.callError(ctx, err)
		}
	}
	for _, a := range as.afterAuthFuncs {
		if err := a(ctx); err != nil {
			return as.callError(ctx, err)
		}
	}

	return nil
}

func (as *AuthService) callError(ctx *AuthContext, err error) error {
	for _, a := range as.errFuncs {
		if e := a(ctx, err); e != nil {
			err = e
		}
	}
	return err
}
