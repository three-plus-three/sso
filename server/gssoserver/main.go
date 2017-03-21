package main

import (
	"cn/com/hengwei/sso/server"
	"flag"

	_ "github.com/lib/pq"
)

func main() {
	dbConfig := &server.DbConfig{}
	config := &server.Config{
		AuthConfig: dbConfig,
		//UrlPrefix: "hw",
		HeaderTitleText: "单点登录系统 v1.0",
		FooterTitleText: "© 2017 恒维信息技术(上海)有限公司, 保留所有版权。",
		TicketProtocol:  "jwt",
		TicketConfig:    map[string]interface{}{},
	}

	flag.StringVar(&config.ListenAt, "listen", ":9031", "")
	flag.StringVar(&dbConfig.DbType, "dbType", "postgres", "")
	flag.StringVar(&dbConfig.Address, "dbHost", "127.0.0.1", "")
	flag.StringVar(&dbConfig.Port, "dbPort", "5432", "")
	flag.StringVar(&dbConfig.DbName, "dbName", "tpt_models", "")
	flag.StringVar(&dbConfig.Username, "dbUsername", "tpt", "")
	flag.StringVar(&dbConfig.Password, "dbPassword", "extreme", "")

	flag.Parse()
	if nil != flag.Args() && 0 != len(flag.Args()) {
		flag.Usage()
		return
	}

	server.Run(config)
}
