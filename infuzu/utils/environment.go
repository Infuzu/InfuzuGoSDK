package infuzu

import "os"

func GetEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func PreconfiguredGetEnv(key, defaultValue string) func() string {
	return func() string {
		return GetEnv(key, defaultValue)
	}
}

func PreconfiguredGetEnvFactory(key string, defaultValueFactory func() string) func() string {
	return func() string {
		return GetEnv(key, defaultValueFactory())
	}
}
