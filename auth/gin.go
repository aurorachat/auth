package auth

import (
	"github.com/aurorachat/jwt-tokens/tokens"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"slices"
)

func Authorization(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authToken := c.Request.Header.Get("Authorization")
		if authToken == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		claimsOrNil, err := tokens.ValidateToken(authToken)

		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims := *claimsOrNil

		c.Set("jwt-claims", claims)

		if len(allowedRoles) != 0 {
			if !slices.Contains(allowedRoles, claims["role"].(string)) {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}

		c.Next()
	}
}

func RetrieveClaims(c *gin.Context) *jwt.MapClaims {
	rawClaims, found := c.Get("jwt-claims")

	if !found {
		return nil
	}

	claims := rawClaims.(jwt.MapClaims)

	return &claims
}
