package infuzu

var privateKey string

func SetPrivateKey(key string) {
	privateKey = key
}

func GetSetPrivateKey() string {
	return privateKey
}
