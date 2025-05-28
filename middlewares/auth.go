package middlewares

import (
	"auth-service/config"
	"auth-service/helper"
	"auth-service/models"
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"gorm.io/gorm"
)

type AuthMiddleware struct {
	Db      *gorm.DB // Replace with your actual DB interface
	JwksURL string
}

func (am *AuthMiddleware) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get token from cookie
		cookie, err := r.Cookie("access_token")
		if err != nil {
			helper.WriteJsonError(w, http.StatusUnauthorized, "Authentication required")
			return
		}
		ctx, _ := context.WithTimeout(context.TODO(), time.Second*5)
		jwks, err := jwk.Fetch(ctx,
			am.JwksURL,
		)
		if err != nil {
			helper.WriteJsonError(w, http.StatusUnauthorized, err.Error())
			return
		}
		key, ok := jwks.Key(0)
		if !ok {
			helper.WriteJsonError(w, http.StatusUnauthorized, "change this message")
			return
		}
		// Parse and verify token
		token, err := jwt.Parse(
			[]byte(cookie.Value),
			jwt.WithKey(jwa.RS256(), key),
			jwt.WithValidate(true),
		)
		if err != nil {
			config.Config.Logger.Warn(err)
			helper.WriteJsonError(w, http.StatusUnauthorized, "Invalid token")
			return
		}

		// Extract user ID from token
		userIDStr, ok := token.Subject()
		if !ok {
			helper.WriteJsonError(w, http.StatusUnauthorized, "Invalid token")
			config.Config.Logger.Debug("UserID does not exist in the token")
			return
		}
		userID, err := strconv.ParseUint(userIDStr, 10, 32)
		if err != nil {
			helper.WriteJsonError(w, http.StatusUnauthorized, "Invalid token")
			config.Config.Logger.Debug("Error while parsing UserID received from the token")
			return
		}

		// Fetch user from database
		var user models.User
		err = am.Db.Where("id =?", userID).Find(&user).Error
		if err != nil {
			http.Error(w, "User not found", http.StatusUnauthorized)
			config.Config.Logger.Debugf("User not found in DB with %d userID", userID)
			return
		}

		// Add user and token to request context
		ctx = context.WithValue(r.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, TokenContextKey, token)

		// Call next handler with updated context
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func GetUserFromContext(ctx context.Context) *models.User {
	if user, ok := ctx.Value(UserContextKey).(models.User); ok {
		return &user
	}
	return nil
}
