package users

import (
	"bytes"
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
