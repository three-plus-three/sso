package main

import (
	"flag"

	_ "github.com/lib/pq"
	"github.com/three-plus-three/sso/server"
)

func main() {
	dbConfig := &server.DbConfig{}
	config := &server.Config{
		UserConfig: dbConfig,
		//UrlPrefix: "hw",
		HeaderTitleText: "单点登录系统 v1.0",
		FooterTitleText: "© 2019",
		TicketProtocol:  "jwt",
		TicketConfig:    map[string]interface{}{},
	}

	flag.StringVar(&config.ListenAt, "listen", ":9031", "")
	flag.StringVar(&dbConfig.DbType, "dbType", "postgres", "")
	flag.StringVar(&dbConfig.DbURL, "dbURL", "host=127.0.0.1 dbname=ssotest user=ssotest password=123456 sslmode=disable", "")

	flag.Parse()
	if nil != flag.Args() && 0 != len(flag.Args()) {
		flag.Usage()
		return
	}

	server.Run(config)
}
