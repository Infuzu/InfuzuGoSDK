package infuzu

import (
	"bytes"
	"fmt"
	authenticate "github.com/infuzu/infuzu-go-sdk/infuzu/authentication/authenticate"
	infuzu "github.com/infuzu/infuzu-go-sdk/infuzu/authentication/requests"
	shortcuts "github.com/infuzu/infuzu-go-sdk/infuzu/authentication/shortcuts"
	"github.com/labstack/echo/v4"
	"io"
)

func VerifyAndIdentifyMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		signature := c.Request().Header.Get(shortcuts.SignatureHeaderName)
		message, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return fmt.Errorf("error reading request body: %w", err)
		}
		c.Request().Body = io.NopCloser(bytes.NewBuffer(message))
		var application *infuzu.Application
		application, err = authenticate.ConvertMessageSignatureToApplicationAndVerify(signature, string(message))
		if err != nil {
			c.Set("application", nil)
		} else {
			c.Set("application", application)
		}
		return next(c)
	}
}
