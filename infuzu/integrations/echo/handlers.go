package infuzu

import (
	"fmt"
	authenticate "github.com/infuzu/infuzu-go-sdk/infuzu/authentication/authenticate"
	shortcuts "github.com/infuzu/infuzu-go-sdk/infuzu/authentication/shortcuts"
	"github.com/labstack/echo/v4"
	"io"
	"net/http"
)

func EnsureThereIsValidApplication(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		application := c.Get("application")
		if application == nil || !authenticate.ApplicationIsValid(application) {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "Access Denied - Signature is invalid"})
		}
		return next(c)
	}
}

func EnsureApplicationIsInternal(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		application := c.Get("application")
		if application == nil || !authenticate.ApplicationIsInternal(application) {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "Access Denied - Signature is invalid"})
		}
		return next(c)
	}
}

func EnsureValidApplicationIDs(allowedAppIDs []string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			application := c.Get("application")
			if application == nil || !authenticate.ApplicationIsInList(application, allowedAppIDs) {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "Access Denied - Application ID is not allowed"})
			}
			return next(c)
		}
	}
}

func EnsureMessageIsValidFromPublicKey(publicKey interface{}) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			signature := c.Request().Header.Get(shortcuts.SignatureHeaderName)
			message, err := io.ReadAll(c.Request().Body)
			if err != nil {
				return fmt.Errorf("error reading request body: %w", err)
			}
			c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, int64(len(message)))
			var isValid bool
			isValid, err = authenticate.VerifyDiverseMessageSignature(string(message), signature, publicKey)
			if err != nil || !isValid {
				return c.JSON(http.StatusForbidden, map[string]string{"error": "Access Denied - Message is not properly signed"})
			}
			return next(c)
		}
	}
}

func EnsureMessageIsValidFromPublicKeys(publicKeys []interface{}) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			signature := c.Request().Header.Get(shortcuts.SignatureHeaderName)
			message, err := io.ReadAll(c.Request().Body)
			if err != nil {
				return fmt.Errorf("error reading request body: %w", err)
			}
			c.Request().Body = http.MaxBytesReader(c.Response(), c.Request().Body, int64(len(message)))
			for _, publicKey := range publicKeys {
				isValid, err := authenticate.VerifyDiverseMessageSignature(string(message), signature, publicKey)
				if err == nil && isValid {
					return next(c)
				}
			}
			return c.JSON(http.StatusForbidden, map[string]string{"error": "Access Denied - Message is not properly signed"})
		}
	}
}
