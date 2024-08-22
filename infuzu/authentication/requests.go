package infuzu

import (
	base "InfuzuGOSDK/infuzu"
	constants "InfuzuGOSDK/infuzu/constants"
	utils "InfuzuGOSDK/infuzu/utils"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type Application struct {
	ID          *string `json:"id"`
	Name        *string `json:"name"`
	Description *string `json:"description,omitempty"`
	IsInternal  *bool   `json:"isInternal,omitempty"`
}

func (a Application) String() string {
	return fmt.Sprintf("%s (%s)", *a.Name, *a.ID)
}

type AuthenticationKey struct {
	Valid          *bool        `json:"valid"`
	ID             *string      `json:"id"`
	Name           *string      `json:"name"`
	PublicKeyB64   *string      `json:"publicKeyB64"`
	PrivateKeyHash *string      `json:"privateKeyHash,omitempty"`
	Application    *Application `json:"application,omitempty"`
}

func (ak AuthenticationKey) String() string {
	if ak.Valid != nil && *ak.Valid {
		return fmt.Sprintf("%s (%s)", *ak.Name, (*ak.Application).String())
	}
	return fmt.Sprintf("%s (INVALID)", *ak.Name)
}

func (ak AuthenticationKey) PublicKey() (*IPublicKey, error) {
	if ak.PublicKeyB64 == nil {
		return nil, errors.New("infuzu/authentication/requests.go authentication key has no public key")
	}
	var pk IPublicKey
	err := pk.FromBase64(*ak.PublicKeyB64)
	return &pk, err
}

func fetchApplicationInformation(keyID string) (*AuthenticationKey, error) {
	url := constants.IKeysBaseUrl + strings.ReplaceAll(constants.IKeysKeyPairEndpoint, "<str:key_id>", keyID)
	var resp *http.Response
	var err error
	resp, err = base.SignedRequest("GET", url, nil, nil, nil)
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

	var application Application
	if err = json.Unmarshal(applicationJson, &application); err != nil {
		return nil, err
	}

	var keyJson []byte
	keyJson, err = json.Marshal(keyInformation)
	if err != nil {
		return nil, err
	}

	var authenticationKey AuthenticationKey
	if err = json.Unmarshal(keyJson, &authenticationKey); err != nil {
		return nil, err
	}
	authenticationKey.Application = &application
	return &authenticationKey, nil
}

var applicationInfoCache = utils.NewCacheSystem(fetchApplicationInformation, 600, 100)

func GetApplicationInformation(keyID string) (*AuthenticationKey, error) {
	result, err := applicationInfoCache.Get(keyID, false, nil, 0, keyID)
	if err != nil {
		return nil, err
	}
	return result.(*AuthenticationKey), nil
}
