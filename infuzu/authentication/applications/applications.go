package infuzu

import (
	auth "InfuzuGOSDK/infuzu/authentication/requests"
	constants "InfuzuGOSDK/infuzu/constants"
	requests "InfuzuGOSDK/infuzu/requests"
	utils "InfuzuGOSDK/infuzu/utils"
	"encoding/json"
	"errors"
	"fmt"
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
	resp, err = requests.SignedRequest("GET", url, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
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

	_, valid := results["valid"]
	keyInfo := results["valid"]
	if !valid {
		keyInfo = results["invalid"]
	}

	keyInformation := keyInfo.(map[string]interface{})
	applicationInfo := keyInformation["application"].(map[string]interface{})
	delete(keyInformation, "application")

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
	keyJson, err = json.Marshal(keyInformation)
	if err != nil {
		return nil, err
	}

	var authenticationKey auth.AuthenticationKey
	if err = json.Unmarshal(keyJson, &authenticationKey); err != nil {
		return nil, err
	}
	authenticationKey.Application = &application
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
