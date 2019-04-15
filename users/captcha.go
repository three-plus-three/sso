package users

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/mojocn/base64Captcha"
)

//ConfigJsonBody json request body.
type ConfigJsonBody struct {
	Id              string
	CaptchaType     string
	VerifyValue     string
	ConfigAudio     base64Captcha.ConfigAudio
	ConfigCharacter base64Captcha.ConfigCharacter
	ConfigDigit     base64Captcha.ConfigDigit
}

// base64Captcha create http handler
func GenerateCaptcha(config base64Captcha.ConfigDigit) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		id := query.Get("captcha_id")

		//GenerateCaptcha 第一个参数为空字符串,包会自动在服务器一个随机种子给你产生随机uiid.
		captchaKey, captchaCode := base64Captcha.GenerateCaptcha(id, config)
		base64String := base64Captcha.CaptchaWriteToBase64Encoding(captchaCode)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":     true,
			"data":        base64String,
			"captcha_key": captchaKey,
			"msg":         "success",
		})
	}
}

var failResponse = map[string]interface{}{"success": false, "data": "验证失败", "msg": "captcha failed"}
var okResponse = map[string]interface{}{"success": true, "data": "验证通过", "msg": "captcha verified"}

// base64Captcha verify http handler
func CaptchaVerify(config base64Captcha.ConfigDigit) func(w http.ResponseWriter, r *http.Request) (bool, error) {
	return func(w http.ResponseWriter, r *http.Request) (bool, error) {

		var captchaKey, verifyValue string

		// Parse the body depending on the content type.
		switch r.Header.Get("Content-Type") {
		case "application/x-www-form-urlencoded":
			err := r.ParseMultipartForm(32 << 20)
			if err != nil {
				return false, errors.New("读参数失败: " + err.Error())
			}
			captchaKey = r.FormValue("captcha_key")
			verifyValue = r.FormValue("captcha_value")

		case "multipart/form-data":
			err := r.ParseMultipartForm(32 << 20)
			if err != nil {
				return false, errors.New("读参数失败: " + err.Error())
			}
			captchaKey = r.FormValue("captcha_key")
			verifyValue = r.FormValue("captcha_value")
		case "application/json":
			fallthrough
		case "text/json":
			var form struct {
				CaptchaKey string `json:"captcha_key"`
				Value      string `json:"captcha_value"`
			}

			if r.Body != nil {
				err := json.NewDecoder(r.Body).Decode(&form)
				if err != nil {
					return false, errors.New("读参数失败: " + err.Error())
				}
			}

			captchaKey = form.CaptchaKey
			verifyValue = form.Value
		}

		if captchaKey == "" || verifyValue == "" {
			return false, errors.New("参数为空")
		}

		//比较图像验证码
		return base64Captcha.VerifyCaptcha(captchaKey, verifyValue), nil
	}
}

type captchaWrapper struct {
	logger  *log.Logger
	inner   UserManager
	captcha interface{}
}

func (ow *captchaWrapper) Read(loginInfo *LoginInfo) (Authentication, error) {
	if count := ow.inner.FailCount(loginInfo.Username); count > 0 {
		if loginInfo.CaptchaKey == "" || loginInfo.CaptchaValue == "" {
			return nil, ErrCaptchaMissing
		}

		//比较图像验证码
		if !base64Captcha.VerifyCaptcha(loginInfo.CaptchaKey, loginInfo.CaptchaValue) {
			return nil, ErrCaptchaKey
		}
	}
	return ow.inner.Read(loginInfo)
}

func (ow *captchaWrapper) Lock(username string) error {
	return ow.inner.Lock(username)
}

func (ow *captchaWrapper) Unlock(username string) error {
	return ow.inner.Unlock(username)
}

func (ow *captchaWrapper) Locked() ([]LockedUser, error) {
	return ow.inner.Locked()
}

func (ow *captchaWrapper) FailCount(username string) int {
	return ow.inner.FailCount(username)
}

func (ow *captchaWrapper) Auth(auth Authentication, loginInfo *LoginInfo) (*UserInfo, error) {
	return ow.inner.Auth(auth, loginInfo)
}

func CaptchaWrap(um UserManager, logger *log.Logger) UserManager {
	return &captchaWrapper{
		logger: logger,
		inner:  um,
	}
}
