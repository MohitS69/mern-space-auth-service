package middlewares

import "net/http"


type ContextKey string

const (
	UserContextKey  ContextKey = "user"
	TokenContextKey ContextKey = "token"
)


// Middleware type - function that wraps http.HandlerFunc
type Middleware func(http.HandlerFunc) http.HandlerFunc

// MiddlewareFunc type - function that wraps http.Handler
type MiddlewareFunc func(http.Handler) http.Handler

func ChainMiddleware(middlewares ...Middleware) Middleware {
	return func(next http.HandlerFunc) http.HandlerFunc {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}
