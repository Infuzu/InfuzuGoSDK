package infuzu

import (
	"github.com/gin-gonic/gin"
	authenticate "github.com/infuzu/InfuzuGoSDK/infuzu/authentication/authenticate"
	shortcuts "github.com/infuzu/InfuzuGoSDK/infuzu/authentication/shortcuts"
	"net/http"
)

func VerifyAndIdentifyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		signature := c.GetHeader(shortcuts.SignatureHeaderName)
		message, _ := c.GetRawData()
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, int64(len(message)))
		application, err := authenticate.ConvertMessageSignatureToApplicationAndVerify(signature, string(message))
		if err != nil {
			c.Set("application", nil)
		} else {
			c.Set("application", application)
		}
		c.Next()
	}
}
