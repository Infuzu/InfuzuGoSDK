package infuzu

import (
	"encoding/json"
	"errors"
	"fmt"
	auth "github.com/infuzu/InfuzuGoSDK/infuzu/authentication/requests"
	constants "github.com/infuzu/InfuzuGoSDK/infuzu/constants"
	requests "github.com/infuzu/InfuzuGoSDK/infuzu/requests"
	utils "github.com/infuzu/InfuzuGoSDK/infuzu/utils"
	"net/http"
	"strings"
)

func FetchMock(keyID string) (*auth.AuthenticationKey, error) {
	return fetchApplicationInformation(keyID)
}

func fetchApplicationInformation(keyID string) (*auth.AuthenticationKey, error) {
	url := constants.IKeysBaseUrl() + strings.ReplaceAll(constants.IKeysKeyPairEndpoint(), "<str:key_id>", keyID)
	var resp *http.Response
	var err error
	resp, err = requests.SignedClient.Request("GET", url, nil, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close response body: %w", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(
			fmt.Sprintf(
				"infuzu/authentication/requests.go failed to fetch application information: %s", resp.Status,
			),
		)
	}

	var results map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}

	keyInfo, valid := results["valid"].(map[string]interface{})
	if !valid {
		keyInfo, _ = results["invalid"].(map[string]interface{})
	}

	applicationInfo, ok := keyInfo["application"].(map[string]interface{})
	if !ok {
		return nil, errors.New("missing or invalid application info")
	}
	delete(keyInfo, "application")

	var applicationJson []byte
	applicationJson, err = json.Marshal(applicationInfo)
	if err != nil {
		return nil, err
	}

	var application auth.Application
	if err = json.Unmarshal(applicationJson, &application); err != nil {
		return nil, err
	}

	var keyJson []byte
	keyJson, err = json.Marshal(keyInfo)
	if err != nil {
		return nil, err
	}

	var authenticationKey auth.AuthenticationKey
	if err = json.Unmarshal(keyJson, &authenticationKey); err != nil {
		return nil, err
	}
	authenticationKey.Application = &application
	authenticationKey.Valid = &valid

	return &authenticationKey, nil
}

var applicationInfoCache = utils.NewCacheSystem(fetchApplicationInformation, 600, 100)

func GetApplicationInformation(keyID string) (*auth.AuthenticationKey, error) {
	result, err := applicationInfoCache.Get(keyID, false, nil, 0, keyID)
	if err != nil {
		return nil, err
	}
	return result.(*auth.AuthenticationKey), nil
}
