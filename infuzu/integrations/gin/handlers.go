package infuzu

import (
	auth "InfuzuGOSDK/infuzu/authentication"
	"github.com/gin-gonic/gin"
	"net/http"
)

func EnsureThereIsValidApplication() gin.HandlerFunc {
	return func(c *gin.Context) {
		application, exists := c.Get("application")
		if !exists || !auth.ApplicationIsValid(application) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied - Signature is invalid"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func EnsureApplicationIsInternal() gin.HandlerFunc {
	return func(c *gin.Context) {
		application, exists := c.Get("application")
		if !exists || !auth.ApplicationIsInternal(application) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied - Signature is invalid"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func EnsureValidApplicationIDs(allowedAppIDs []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		application, exists := c.Get("application")
		if !exists || !auth.ApplicationIsInList(application, allowedAppIDs) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied - Application ID is not allowed"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func EnsureMessageIsValidFromPublicKey(publicKey interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		signature := c.GetHeader(auth.SignatureHeaderName)
		message, _ := c.GetRawData()
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, int64(len(message)))
		isValid, err := auth.VerifyDiverseMessageSignature(string(message), signature, publicKey)
		if err != nil || !isValid {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied - Message is not properly signed"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func EnsureMessageIsValidFromPublicKeys(publicKeys []interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		signature := c.GetHeader(auth.SignatureHeaderName)
		message, _ := c.GetRawData()
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, int64(len(message)))
		for _, publicKey := range publicKeys {
			isValid, err := auth.VerifyDiverseMessageSignature(string(message), signature, publicKey)
			if err == nil && isValid {
				c.Next()
				return
			}
		}
		c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied - Message is not properly signed"})
		c.Abort()
	}
}
