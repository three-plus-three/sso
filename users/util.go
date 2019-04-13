package users

import (
	"bytes"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"time"
)

func ParseTime(layout, s string) time.Time {
	if layout != "" {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t
		}
	}

	for _, layout := range []string{time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999Z07:00"} {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t
		}
	}
	return time.Time{}
}

// ReplacePlaceholders 将 sql 语句中的 ? 改成 $x 形式
func ReplacePlaceholders(sql string) string {
	buf := &bytes.Buffer{}
	i := 0
	for {
		p := strings.Index(sql, "?")
		if p == -1 {
			break
		}

		if len(sql[p:]) > 1 && sql[p:p+2] == "??" { // escape ?? => ?
			buf.WriteString(sql[:p])
			buf.WriteString("?")
			if len(sql[p:]) == 1 {
				break
			}
			sql = sql[p+2:]
		} else {
			i++
			buf.WriteString(sql[:p])
			fmt.Fprintf(buf, "$%d", i)
			sql = sql[p+1:]
		}
	}

	buf.WriteString(sql)
	return buf.String()
}

func StringWith(params map[string]interface{}, key, defaultValue string) (string, bool) {
	return stringWith(params, key, defaultValue)
}

func stringWith(params map[string]interface{}, key, defaultValue string) (string, bool) {
	o, ok := params[key]
	if !ok || o == nil {
		return defaultValue, true
	}

	s, ok := o.(string)
	if !ok {
		return "", false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultValue, true
	}
	return s, true
}

// NullTime represents a time.Time that may be null. NullTime implements the
// sql.Scanner interface so it can be used as a scan destination, similar to
// sql.NullString.
type NullTime struct {
	Time  time.Time
	Valid bool // Valid is true if Time is not NULL
}

// Scan implements the Scanner interface.
func (nt *NullTime) Scan(value interface{}) error {
	switch s := value.(type) {
	case time.Time:
		nt.Time = s
		nt.Valid = true
		return nil
	case string:
		return nt.Parse(s)
	case []byte:
		return nt.Parse(string(s))
	default:
		return errors.New("unknow value - " + fmt.Sprintf("%T %s", value, value))
	}
}

func (nt NullTime) Parse(s string) error {
	for _, layout := range []string{} {
		t, err := time.Parse(layout, s)
		if err == nil {
			nt.Time = t
			nt.Valid = true
			return nil
		}
	}
	return errors.New("unknow value - " + s)
}

// Value implements the driver Valuer interface.
func (nt NullTime) Value() (driver.Value, error) {
	if !nt.Valid {
		return nil, nil
	}
	return nt.Time, nil
}
