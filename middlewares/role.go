package middlewares

import (
	"auth-service/models"
	"net/http"
)

func RequireRole(roles ...models.RoleType) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}
			found := false
			for _, role := range roles {
				if user.Role == role {
					found = true
					break
				}
			}
			if !found {
				http.Error(w, "Insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		}
	}
}
