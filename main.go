package main

import (
	application "github.com/infuzu/InfuzuGoSDK/infuzu/authentication/applications"
	constants "github.com/infuzu/InfuzuGoSDK/infuzu/constants"
	utils "github.com/infuzu/InfuzuGoSDK/infuzu/utils"
	"github.com/joho/godotenv"
	"log"
	"os"
)

func init() {
	log.SetOutput(os.Stdout)
	log.Println("Initializing")
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	constants.SetPrivateKey(utils.GetEnv("INFUZU_SECRET_KEY", ""))
}

func main() {
	results, err := application.FetchMock("68c99b8c93414c19b430beb8e94112b7")
	if err != nil {
		log.Fatal(err)
	}
	log.Println(results)
}
