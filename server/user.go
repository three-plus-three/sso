package server

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

var localAddressList, _ = net.LookupHost("localhost")

// DefaultUserHandler 缺省 UserHandler
var DefaultUserHandler = createDbUserHandler

type IPChecker interface {
	Contains(net.IP) bool
}

var _ IPChecker = &net.IPNet{}

type User interface {
	Name() string
	Auth(address, password string) error
	Data() map[string]interface{}
}

type UserImpl struct {
	externalVerify    VerifyFunc
	verify            func(password, excepted string) error
	name              string
	password          string
	lockedAt          time.Time
	lockedTimeExpires time.Duration
	ingressIPList     []IPChecker
	data              map[string]interface{}
}

func (u *UserImpl) Name() string {
	return u.name
}

func (u *UserImpl) Password() string {
	return u.password
}

const (
	HeaderXForwardedFor = "X-Forwarded-For"
	HeaderXRealIP       = "X-Real-IP"
)

func RealIP(req *http.Request) string {
	ra := req.RemoteAddr
	if ip := req.Header.Get(HeaderXForwardedFor); ip != "" {
		ra = ip
	} else if ip := req.Header.Get(HeaderXRealIP); ip != "" {
		ra = ip
	} else {
		ra, _, _ = net.SplitHostPort(ra)
	}
	return ra
}

func (u *UserImpl) isValid(currentAddr string) (bool, error) {
	if len(u.ingressIPList) != 0 {
		ip := net.ParseIP(currentAddr)
		if ip == nil {
			return false, errors.New("client address is invalid - '" + currentAddr + "'")
		}

		blocked := true
		for _, checker := range u.ingressIPList {
			if checker.Contains(ip) {
				blocked = false
				break
			}
		}

		if blocked {
			if "127.0.0.1" == currentAddr {
				blocked = false
			} else {
				for _, addr := range localAddressList {
					if currentAddr == addr {
						blocked = false
						break
					}
				}

				if blocked {
					return false, ErrUserIPBlocked
				}
			}
		}
	}

	if !u.lockedAt.IsZero() {
		if u.lockedTimeExpires == 0 {
			return false, ErrUserLocked
		}
		if time.Now().Before(u.lockedAt.Add(u.lockedTimeExpires)) {
			return false, ErrUserLocked
		}
	}
	return true, nil
}

func (u *UserImpl) Data() map[string]interface{} {
	return u.data
}

func (u *UserImpl) Auth(address, password string) error {
	ok, err := u.isValid(address)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("user is inused")
	}

	if u.externalVerify != nil {
		if typ := u.data["source"]; typ != nil {
			if verifyType := fmt.Sprint(typ); verifyType != "" && verifyType != "builin" {
				return u.externalVerify(verifyType, u.name, password)
			}
		}
	}

	exceptedPassword := u.Password()
	if exceptedPassword == "" {
		return ErrPasswordEmpty
	}

	err = u.verify(password, exceptedPassword)
	if err != nil {
		if err == ErrSignatureInvalid {
			return ErrPasswordNotMatch
		}
		return err
	}
	return nil
}

type ipRange struct {
	start, end uint32
}

func (r *ipRange) String() string {
	var a, b [4]byte
	binary.BigEndian.PutUint32(a[:], r.start)
	binary.BigEndian.PutUint32(b[:], r.end)
	return net.IP(a[:]).String() + "-" +
		net.IP(b[:]).String()
}

func (r *ipRange) Contains(ip net.IP) bool {
	if ip.To4() == nil {
		return false
	}

	v := binary.BigEndian.Uint32(ip.To4())
	return r.start <= v && v <= r.end
}

func IPRange(start, end net.IP) (IPChecker, error) {
	if start.To4() == nil {
		return nil, errors.New("ip range 不支持 IPv6")
	}
	if end.To4() == nil {
		return nil, errors.New("ip range 不支持 IPv6")
	}
	s := binary.BigEndian.Uint32(start.To4())
	e := binary.BigEndian.Uint32(end.To4())
	return &ipRange{start: s, end: e}, nil
}

func IPRangeWith(start, end string) (IPChecker, error) {
	s := net.ParseIP(start)
	if s == nil {
		return nil, errors.New(start + " is invalid address")
	}
	e := net.ParseIP(end)
	if e == nil {
		return nil, errors.New(end + " is invalid address")
	}
	return IPRange(s, e)
}
