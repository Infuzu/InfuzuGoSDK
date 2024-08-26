package infuzu

import (
	"bytes"
	"github.com/gin-gonic/gin"
	authenticate "github.com/infuzu/infuzu-go-sdk/infuzu/authentication/authenticate"
	shortcuts "github.com/infuzu/infuzu-go-sdk/infuzu/authentication/shortcuts"
	"io"
)

func VerifyAndIdentifyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		signature := c.GetHeader(shortcuts.SignatureHeaderName)
		message, _ := c.GetRawData()
		c.Request.Body = io.NopCloser(bytes.NewBuffer(message))
		application, err := authenticate.ConvertMessageSignatureToApplicationAndVerify(signature, string(message))
		if err != nil {
			c.Set("application", nil)
		} else {
			c.Set("application", application)
		}
		c.Next()
	}
}
