package client

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrCookieNotFound = errors.New("session cookie isn't found")
var ErrCookieEmpty = errors.New("session cookie is empty")

const (
	// DefaultSessionKey default key value
	DefaultSessionKey     = "PLAY_SESSION"
	SESSION_ID_KEY        = "session_id"
	SESSION_VALID_KEY     = "_valid"
	SESSION_USER_KEY      = "user"
	SESSION_EXPIRE_KEY    = "_expire"
	SESSION_ISSUED_AT_KEY = "issued_at"
)

func SessionIsExpiredOrMissing(exp string) bool {
	if exp == "session" {
		return false
	} else if expInt, _ := strconv.Atoi(exp); int64(expInt) < time.Now().Unix() {
		return true
	}
	return false
}

func SessionIsInvalid(exp string) bool {
	return strings.ToLower(exp) != "true"
}

// TimeoutExpiredOrMissing returns a boolean of whether the session
// cookie is either not present or present but beyond its time to live; i.e.,
// whether there is not a valid session.
func TimeoutExpiredOrMissing(values url.Values) bool {
	list, present := values[SESSION_EXPIRE_KEY]
	if !present {
		return false
	}
	if len(list) == 0 {
		return false
	}

	return SessionIsExpiredOrMissing(list[len(list)-1])
}

func IsInvalid(values url.Values) bool {
	list, present := values[SESSION_VALID_KEY]
	if !present {
		return false
	}
	if len(list) == 0 {
		return false
	}
	exp := list[len(list)-1]
	return SessionIsInvalid(exp)
}

// getSessionExpiration retrieves the cookie's time to live as a
// string of either the number of seconds, for a persistent cookie, or
// "session".
func GetExpiration(t time.Time) string {
	if t.IsZero() {
		return "session"
	}
	return strconv.FormatInt(t.Unix(), 10)
}

// Sign a given string with the app-configured secret key.
// If no secret key is set, returns the empty string.
// Return the signature in base64 (URLEncoding).
func Sign(message string, h func() hash.Hash, secretKey []byte) string {
	if len(secretKey) == 0 {
		return ""
	}
	mac := hmac.New(h, secretKey)
	io.WriteString(mac, message)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify returns true if the given signature is correct for the given message.
// e.g. it matches what we generate with Sign()
func Verify(message, sig string, h func() hash.Hash, secretKey []byte) bool {
	return hmac.Equal([]byte(sig), []byte(Sign(message, h, secretKey)))
}

func Encode(values url.Values, h func() hash.Hash, secretKey []byte) string {
	if id := values.Get(SESSION_ID_KEY); id == "" {
		values.Set(SESSION_ID_KEY, GenerateID())
	}
	values.Set("_ID", values.Get(SESSION_ID_KEY))

	if _, ok := values[SESSION_EXPIRE_KEY]; !ok {
		values.Set(SESSION_EXPIRE_KEY, GetExpiration(time.Now().Add(10*time.Minute)))
	}
	values.Set("_TS", values.Get(SESSION_EXPIRE_KEY))

	if _, ok := values[SESSION_VALID_KEY]; !ok {
		values.Set(SESSION_VALID_KEY, "false")
	}

	s := values.Encode()
	return Sign(s, h, secretKey) + "-" + s
}

func GetValuesFromString(value string, verify func(data, sig string) bool) (url.Values, error) {
	if value == "" {
		return nil, ErrCookieEmpty
	}

	// Separate the data from the signature.
	hyphen := strings.Index(value, "-")
	if hyphen == -1 || hyphen >= len(value)-1 {
		return nil, errors.New("session cookie has invalid value")
	}
	data := value[hyphen+1:]

	// Verify the signature.
	if verify != nil {
		if !verify(data, value[:hyphen]) {
			return nil, errors.New("session cookie signature failed")
		}
	}

	values, e := url.ParseQuery(data)
	if nil != e {
		return nil, errors.New("session cookie decode fail, " + e.Error())
	}

	if IsInvalid(values) {
		return nil, errors.New("session is invalid")
	}

	if TimeoutExpiredOrMissing(values) {
		return nil, errors.New("session is timeout")
	}
	return values, nil
}

func GetValuesFromCookie(req *http.Request, sessionKey string, verify func(data, sig string) bool) (url.Values, error) {
	cookie, err := req.Cookie(sessionKey)
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, ErrCookieNotFound
		}
		return nil, err
	}
	return GetValuesFromString(cookie.Value, verify)
}

func GetValues(req *http.Request, sessionKey string, h func() hash.Hash, secretKey []byte) (url.Values, error) {
	return GetValuesFromCookie(req, sessionKey, func(data, sig string) bool {
		if secretKey == nil {
			return true
		}
		return Verify(data, sig, h, secretKey)
	})
}
