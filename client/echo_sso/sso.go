package echo_sso

import (
	"errors"

	"github.com/labstack/echo"
	"github.com/three-plus-three/sso/client"
)

type (
	keyExtractor func(echo.Context) (string, error)
)

// SSOWithConfig returns a sso auth middleware with config.
// parameter lookup is a string that is used to extract
// token from the request. Optional. Default value "query".
// Possible values:
// - "query"
// - "cookie"
// - "query_and_cookie"
func SSOWithConfig(lookup, name, service string, ssoClient *client.Client) echo.MiddlewareFunc {
	if lookup == "" {
		lookup = "query_and_cookie"
	}

	if name == "" {
		name = "ticket"
	}

	var extractor = keyFromQuery(name)
	switch lookup {
	case "query":
		extractor = keyFromQuery(name)
	case "cookie":
		extractor = keyFromCookie(name)
	case "query_and_cookie":
		extractor = keyFromQueryAndCookie(name)
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			auth, err := extractor(c)
			if err != nil {
				return echo.NewHTTPError(echo.ErrUnauthorized.Code, err.Error())
			}

			ticket, err := ssoClient.ValidateTicket(auth, service)
			if err != nil {
				if e, ok := err.(*client.Error); ok {
					return echo.NewHTTPError(e.Code, e.Message)
				}
				return echo.NewHTTPError(echo.ErrUnauthorized.Code, err.Error())
			}
			if ticket.Valid {
				return next(c)
			}
			return echo.ErrUnauthorized
		}
	}
}

// keyFromQuery returns a `keyExtractor` that extracts token from the query string.
func keyFromQuery(param string) keyExtractor {
	return func(c echo.Context) (string, error) {
		token := c.QueryParam(param)
		if token == "" {
			return "", errors.New("Missing ticket in the query string")
		}
		return token, nil
	}
}

// keyFromCookie returns a `keyExtractor` that extracts token from the named cookie.
func keyFromCookie(name string) keyExtractor {
	return func(c echo.Context) (string, error) {
		cookie, err := c.Cookie(name)
		if err != nil {
			return "", errors.New("Missing ticket in the cookie")
		}
		return cookie.Value, nil
	}
}

// keyFromQueryAndCookie returns a `keyExtractor` that extracts token from the named cookie.
func keyFromQueryAndCookie(name string) keyExtractor {
	return func(c echo.Context) (string, error) {
		token := c.QueryParam(name)
		if token != "" {
			return token, nil
		}

		cookie, err := c.Cookie(name)
		if err == nil {
			return cookie.Value, nil
		}

		return "", errors.New("Missing ticket in the query string")
	}
}
