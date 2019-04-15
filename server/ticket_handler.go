package server

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
)

// Ticket 票据对象
type Ticket struct {
	Ticket    string
	Username  string
	SessionID string
	ExpiresAt time.Time
	IssuedAt  time.Time
	Data      map[string]interface{}
}

// TicketHandler 票据的管理
type TicketHandler interface {
	NewTicket(uuid, username string, data map[string]interface{}) (*Ticket, error)
	ValidateTicket(ticket string, renew bool) (*Ticket, error)
	RemoveTicket(ticket string) (*Ticket, error)
}

// TicketHandlerFactories 工厂
var TicketHandlerFactories = map[string]func(map[string]interface{}) (TicketHandler, error){}

func init() {
	TicketHandlerFactories["jwt"] = createJwtTicketHandler
}

func createJwtTicketHandler(config map[string]interface{}) (TicketHandler, error) {
	var signingMethodAlg string
	var signingSecret string
	var expiredInternal time.Duration
	if len(config) > 0 {
		if o, ok := config["signing_method"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("协议配置中的 signing_method 的值不是字符串")
			}
			s = strings.TrimSpace(s)
			if s != "" {
				signingMethodAlg = s
			}
		}

		if o, ok := config["signing_secret"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("协议配置中的 signing_secret 的值不是字符串")
			}
			s = strings.TrimSpace(s)
			if s != "" {
				signingSecret = s
			}
		}

		if o, ok := config["timeout"]; ok && o != nil {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("协议配置中的 timeout 的值不是字符串")
			}
			s = strings.TrimSpace(s)
			if s != "" {
				timeout, err := time.ParseDuration(s)
				if err != nil {
					return nil, errors.New("协议配置中的 timeout 的值不是有效的时间")
				}
				expiredInternal = timeout
			}
		}
	}

	if signingMethodAlg == "" {
		signingMethodAlg = "HS256"
	}

	if signingSecret == "" {
		signingSecret = "hengwei_is#very-good"
	}

	if expiredInternal < 1*time.Second {
		expiredInternal = 1 * time.Hour
	}

	signingMethod := jwt.GetSigningMethod(signingMethodAlg)
	if signingMethod == nil {
		return nil, errors.New("signing method '" + signingMethodAlg + "' is unsupported - \"HS256, HS384, HS512\"")
	}
	handler := &jwtTicketHandler{
		signingMethod:   signingMethod,
		secret:          []byte(signingSecret),
		expiredInternal: expiredInternal,
		tickets:         map[string]*Ticket{},
	}
	handler.keyFunc = func(t *jwt.Token) (interface{}, error) {
		// Check the signing method
		if t.Method.Alg() != signingMethod.Alg() {
			return nil, fmt.Errorf("Unexpected jwt signing method=%v", signingMethod.Alg())
		}
		return handler.secret, nil
	}
	return handler, nil
}

type jwtTicketHandler struct {
	signingMethod   jwt.SigningMethod
	secret          []byte
	expiredInternal time.Duration
	ticketMutex     sync.RWMutex
	tickets         map[string]*Ticket
	keyFunc         func(t *jwt.Token) (interface{}, error)
}

func (jh *jwtTicketHandler) NewTicket(uuid, username string, data map[string]interface{}) (*Ticket, error) {
	issuedAt := time.Now()
	expiredAt := issuedAt.Add(jh.expiredInternal)

	token := jwt.NewWithClaims(jh.signingMethod, &jwt.StandardClaims{
		Audience:  username,
		ExpiresAt: expiredAt.Unix(),
		Id:        uuid,
		IssuedAt:  issuedAt.Unix(),
		Issuer:    "hengwei_it",
		//NotBefore int64  `json:"nbf,omitempty"`
		Subject: "tpt",
	})

	res := map[string]interface{}{
		"uuid":       uuid,
		"username":   username,
		"expired_at": expiredAt,
		"issued_at":  issuedAt,
	}

	for k, v := range data {
		found := false
		for _, s := range []string{
			"uuid",
			"username",
			"password",
			"name",
			"expired_at",
			"issued_at",
			"admin"} {
			if s == k {
				found = true
				break
			}
		}
		if found {
			continue
		}
		res[k] = v
	}

	// Generate encoded token and send it as response.
	t, err := token.SignedString(jh.secret)
	if err != nil {
		return nil, echo.NewHTTPError(echo.ErrUnauthorized.Code, "生成 ticket 时对令牌签名发生错误 - "+err.Error())
	}

	jh.ticketMutex.Lock()
	defer jh.ticketMutex.Unlock()

	if jh.tickets == nil {
		jh.tickets = map[string]*Ticket{}
	}

	ticketObject := &Ticket{
		Ticket:    t,
		Username:  username,
		SessionID: uuid,
		ExpiresAt: expiredAt,
		IssuedAt:  issuedAt,
		Data:      res,
	}
	jh.tickets[t] = ticketObject

	return ticketObject, nil
}

func (jh *jwtTicketHandler) ValidateTicket(ticketString string, renew bool) (*Ticket, error) {
	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(ticketString, claims, jh.keyFunc)
	if err != nil {
		return nil, errors.New("无效的 ticket - " + err.Error())
	}
	if !token.Valid {
		return nil, nil
	}

	var ticket *Ticket
	jh.ticketMutex.RLock()
	if jh.tickets != nil {
		ticket = jh.tickets[ticketString]
	}
	jh.ticketMutex.RUnlock()

	if ticket == nil {
		return nil, nil
	}

	if renew {
		ticket.ExpiresAt = time.Now().Add(jh.expiredInternal)
	}

	return ticket, nil
}

func (jh *jwtTicketHandler) RemoveTicket(ticketString string) (*Ticket, error) {
	// claims := &jwt.StandardClaims{}
	// token, err := jwt.ParseWithClaims(ticketString, claims, jh.keyFunc)
	// if err != nil {
	// 	return errors.New("无效的 ticket - " + err.Error())
	// }
	// if !token.Valid {
	// 	return nil
	// }

	var ticket *Ticket
	jh.ticketMutex.Lock()
	if jh.tickets != nil {
		ticket = jh.tickets[ticketString]
		delete(jh.tickets, ticketString)
	}
	jh.ticketMutex.Unlock()

	return ticket, nil
}
