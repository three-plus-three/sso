package sublime_text

var DefaultUserHandler = func(config *Config) (UserManager, error) {
	dbConfig, ok := config.UserConfig.(*DbConfig)
	if !ok {

	}
}
