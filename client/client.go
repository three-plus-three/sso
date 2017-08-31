package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
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

// Ticket 票据对象
type Ticket struct {
	ServiceTicket string                 `json:"ticket,omitempty"`
	SessionID     string                 `json:"session_id,omitempty"`
	Valid         bool                   `json:"valid,omitempty"`
	ExpiresAt     time.Time              `json:"expires_at,omitempty"`
	Claims        map[string]interface{} `json:"claims,omitempty"`
}

type validateTicketResponse struct {
	Ticket
	Error string `json:"error,omitempty"`
}

type newTicketResponse struct {
	ServiceTicket string `json:"ticket,omitempty"`
	Error         string `json:"error,omitempty"`
}

// NewClient 创建一个新客户端
func NewClient(rootURL string) (*Client, error) {
	if strings.HasSuffix(rootURL, "/") {
		rootURL = strings.TrimSuffix(rootURL, "/")
	}

	// if interval == 0 {
	// 	interval = 10 * time.Second
	// }
	c := &Client{
		client:  *http.DefaultClient,
		rootURL: rootURL,
		//interval: interval,
	}
	c.client.Jar, _ = cookiejar.New(nil)

	//c.timer = time.AfterFunc(c.interval, c.onTimeout)
	return c, nil
}

// Client SSO 的客户端
type Client struct {
	client  http.Client
	rootURL string
	headers map[string]string

	/*
		closed     int32
		interval   time.Duration
		timerMutex sync.Mutex
		timer      *time.Timer
	*/

	ticketMutex sync.RWMutex
	tickets     map[string]*Ticket
}

func (c *Client) RootURL() string {
	return c.rootURL
}

func (c *Client) SetHeader(k, v string) {
	if c.headers == nil {
		if v == "" {
			return
		}
		c.headers = map[string]string{}
	}
	if v == "" {
		delete(c.headers, k)
	} else {
		c.headers[k] = v
	}
}

/*
// Close 关闭 SSO 的客户端
func (c *Client) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}
	c.timerMutex.Lock()
	defer c.timerMutex.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	return nil
}

func (c *Client) onTimeout() {
	if atomic.LoadInt32(&c.closed) != 0 {
		return
	}

	defer func() {
		timer := time.AfterFunc(c.interval, c.onTimeout)

		c.timerMutex.Lock()
		defer c.timerMutex.Unlock()

		c.timer.Stop()
		c.timer = timer
	}()

	err := c.Refresh()
	if err != nil {
		log.Println("[sso] 刷新 tickets 失败,", err)
	}
}
*/

// LoginURL 返回一个登录页面的 URL
func (c *Client) LoginURL(service string) string {
	return c.rootURL + "/login?service=" + url.QueryEscape(service)
}

func (c *Client) do(method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	return c.client.Do(req)
}

// NewTicket 创建一个 Ticket
func (c *Client) NewTicket(username, password string) (*Ticket, error) {
	var buf = bytes.NewBuffer(make([]byte, 0, 4*1024))
	err := json.NewEncoder(buf).Encode(map[string]interface{}{
		"username": username,
		"password": password})
	if err != nil {
		return nil, err
	}
	resp, err := c.do("POST", c.rootURL+"/login", buf)
	if err != nil {
		return nil, err
	}
	var bs []byte

	if resp.Body != nil {
		bs, _ = ioutil.ReadAll(resp.Body)
	}
	if resp.StatusCode != http.StatusOK {
		if len(bs) != 0 {
			txt := string(bs)

			if txt == `{"message":"user isn't found"}` {
				return nil, ErrUserNotFound
			}
			if txt == `{"message":"password isn't match"}` {
				return nil, ErrPasswordNotMatch
			}

			return nil, &Error{Code: resp.StatusCode, Message: resp.Status + ": " + txt}
		}

		return nil, &Error{Code: resp.StatusCode, Message: resp.Status}
	}

	newResponse := &newTicketResponse{}
	if err := json.Unmarshal(bs, &newResponse); err != nil {
		return nil, err
	}
	if newResponse.Error != "" {
		return nil, errors.New(newResponse.Error)
	}

	return c.readTicket(newResponse.ServiceTicket)
}

func (c *Client) GetTicket(serviceTicket string) (*Ticket, error) {
	var ticket *Ticket
	c.ticketMutex.RLock()
	if c.tickets != nil {
		ticket = c.tickets[serviceTicket]
	}
	c.ticketMutex.RUnlock()

	if ticket != nil {
		return ticket, nil
	}
	return c.readTicket(serviceTicket)
}

func (c *Client) readTicket(serviceTicket string) (*Ticket, error) {
	ticket, err := c.ValidateTicket(serviceTicket, "")
	if err != nil {
		return nil, err
	}

	c.ticketMutex.Lock()
	defer c.ticketMutex.Unlock()

	if c.tickets == nil {
		c.tickets = map[string]*Ticket{}
	}
	c.tickets[serviceTicket] = ticket
	return ticket, nil
}

func (c *Client) ValidateTicket(serviceTicket, service string) (*Ticket, error) {
	resp, err := c.do("GET",
		c.rootURL+"/verify?ticket="+url.QueryEscape(serviceTicket)+
			"&service="+url.QueryEscape(service), nil)
	if err != nil {
		return nil, err
	}
	var bs []byte

	if resp.Body != nil {
		bs, _ = ioutil.ReadAll(resp.Body)
	}
	if resp.StatusCode != http.StatusOK {
		if len(bs) != 0 {
			return nil, errors.New(resp.Status + ": " + string(bs))
		}
		return nil, errors.New(resp.Status)
	}

	validateResponse := &validateTicketResponse{}
	if err := json.Unmarshal(bs, &validateResponse); err != nil {
		return nil, err
	}
	if validateResponse.Error != "" {
		return nil, errors.New(validateResponse.Error)
	}
	return &validateResponse.Ticket, nil
}

func (c *Client) RemoveTicket(serviceTicket string) error {
	var ticket *Ticket
	c.ticketMutex.Lock()
	if c.tickets != nil {
		ticket = c.tickets[serviceTicket]
		delete(c.tickets, serviceTicket)
	}
	c.ticketMutex.Unlock()

	if ticket == nil {
		return nil
	}

	resp, err := c.do("GET",
		c.rootURL+"/logout?ticket="+url.QueryEscape(serviceTicket), nil)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		var bs []byte
		if resp.Body != nil {
			bs, _ = ioutil.ReadAll(resp.Body)
		}
		if len(bs) != 0 {
			return errors.New(resp.Status + ": " + string(bs))
		}
		return errors.New(resp.Status)
	}

	return nil
}
