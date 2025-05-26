package handlers

import (
	"auth-service/config"
	"auth-service/dto"
	"auth-service/helper"
	"auth-service/middlewares"
	"auth-service/models"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db *gorm.DB
}

func SetupAuthRoutes(db *gorm.DB) *http.ServeMux {
	mux := http.NewServeMux()
	handler := AuthHandler{
		db: db,
	}
	authMiddleware := middlewares.AuthMiddleware{
		Db:      db,
		JwksURL: fmt.Sprintf("http://localhost:%s/.well-known/jwks.json", config.Config.ServerPort),
	}
	mux.HandleFunc("POST /register", handler.register)
	mux.HandleFunc("POST /login", handler.login)
	mux.HandleFunc("GET /self", authMiddleware.RequireAuth(handler.self))
	mux.HandleFunc("GET /refresh", handler.refresh)
	mux.HandleFunc("GET /logout", handler.logout)
	return mux
}

func (u *AuthHandler) register(w http.ResponseWriter, r *http.Request) {
	var payload dto.RegisterUserDto
	if err := helper.ReadJson(w, r, &payload); err != nil {
		helper.WriteJsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := helper.Validator.Struct(payload); err != nil {
		helper.WriteJsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	config.Config.Logger.Infof("New request to register user with email: %s", payload.Email)

	// Check if user already exists
	var existingUser models.User
	result := u.db.Where("email = ?", payload.Email).First(&existingUser)
	if result.Error == nil {
		// User found, already exists
		helper.WriteJsonError(w, http.StatusConflict, "user already exists")
		return
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		// Database error (not "record not found")
		config.Config.Logger.Errorf("Database error checking user existence: %v", result.Error)
		helper.WriteJsonError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		config.Config.Logger.Errorf("Password hashing error: %v", err)
		helper.WriteJsonError(w, http.StatusInternalServerError, "password hashing failed")
		return
	}

	user := models.User{
		Email:     payload.Email,
		Password:  string(hash),
		FirstName: payload.FirstName,
		LastName:  payload.LastName,
		Role:      models.UserRole,
	}

	if err := u.db.Create(&user).Error; err != nil {
		config.Config.Logger.Errorf("User creation error: %v", err)
		helper.WriteJsonError(w, http.StatusInternalServerError, "user creation failed")
		return
	}

	// Generate tokens
	accessTokenRaw, refreshTokenRaw, err := u.generateTokens(user.ID, user.Email)
	if err != nil {
		config.Config.Logger.Errorf("Token generation error: %v", err)
		helper.WriteJsonError(w, http.StatusInternalServerError, "token generation failed")
		return
	}

	// Set cookies
	u.setCookies(w, accessTokenRaw, refreshTokenRaw)

	config.Config.Logger.Infof("User registered successfully: %s", user.Email)
	helper.WriteJson(w, http.StatusCreated, map[string]interface{}{
		"id":        user.ID,
		"email":     user.Email,
		"firstName": user.FirstName,
		"lastName":  user.LastName,
		"role":      user.Role,
	})
}

func (u *AuthHandler) login(w http.ResponseWriter, r *http.Request) {
	var payload dto.LoginUserDto
	if err := helper.ReadJson(w, r, &payload); err != nil {
		helper.WriteJsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := helper.Validator.Struct(payload); err != nil {
		helper.WriteJsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	config.Config.Logger.Infof("New login request for email: %s", payload.Email)

	var user models.User
	result := u.db.Where("email = ?", payload.Email).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			helper.WriteJsonError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		config.Config.Logger.Errorf("Database error during login: %v", result.Error)
		helper.WriteJsonError(w, http.StatusInternalServerError, "database error")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(payload.Password)); err != nil {
		helper.WriteJsonError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Generate tokens
	accessTokenRaw, refreshTokenRaw, err := u.generateTokens(user.ID, user.Email)
	if err != nil {
		config.Config.Logger.Errorf("Token generation error: %v", err)
		helper.WriteJsonError(w, http.StatusInternalServerError, "token generation failed")
		return
	}

	// Set cookies
	u.setCookies(w, accessTokenRaw, refreshTokenRaw)

	config.Config.Logger.Infof("User logged in successfully: %s", user.Email)
	helper.WriteJson(w, http.StatusOK, map[string]interface{}{
		"id":        user.ID,
		"email":     user.Email,
		"firstName": user.FirstName,
		"lastName":  user.LastName,
		"role":      user.Role,
	})
}

func (u *AuthHandler) self(w http.ResponseWriter, r *http.Request) {
	user := middlewares.GetUserFromContext(r.Context())
	if user == nil {
		helper.WriteJsonError(w, http.StatusUnauthorized, "user not found")
		return
	}
	helper.WriteJson(w, http.StatusOK, map[string]interface{}{
		"id":        user.ID,
		"email":     user.Email,
		"firstName": user.FirstName,
		"lastName":  user.LastName,
		"role":      user.Role,
	})
}

func (u *AuthHandler) refresh(w http.ResponseWriter, r *http.Request) {
	refreshTokenFromCookie, err := r.Cookie("refresh_token")
	if err != nil {
		helper.WriteJsonError(w, http.StatusUnauthorized, "refresh token not found")
		return
	}

	token, err := jwt.Parse([]byte(refreshTokenFromCookie.Value),
		jwt.WithKey(jwa.HS256(), []byte(config.Config.RefreshTokenSecret)), jwt.WithValidate(true))
	if err != nil {
		helper.WriteJsonError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	tokenIdStr, ok := token.Subject()
	if !ok {
		helper.WriteJsonError(w, http.StatusUnauthorized, "invalid token format")
		return
	}

	// Convert string back to uint for database query
	tokenId, err := strconv.ParseUint(tokenIdStr, 10, 64)
	if err != nil {
		helper.WriteJsonError(w, http.StatusUnauthorized, "invalid token ID")
		return
	}

	var tokenFromDB models.RefreshToken
	result := u.db.Where("id = ?", tokenId).First(&tokenFromDB)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			helper.WriteJsonError(w, http.StatusUnauthorized, "refresh token not found")
			return
		}
		config.Config.Logger.Errorf("Database error finding refresh token: %v", result.Error)
		helper.WriteJsonError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Check if token is expired
	if time.Now().Unix() > tokenFromDB.ExpiresAt {
		u.db.Delete(&tokenFromDB)
		helper.WriteJsonError(w, http.StatusUnauthorized, "refresh token expired")
		return
	}

	// Delete old refresh token
	if err := u.db.Delete(&tokenFromDB).Error; err != nil {
		config.Config.Logger.Errorf("Error deleting old refresh token: %v", err)
		helper.WriteJsonError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Get user by ID from the refresh token
	var user models.User
	result = u.db.Where("id = ?", tokenFromDB.UserID).First(&user)
	if result.Error != nil {
		config.Config.Logger.Errorf("Error finding user: %v", result.Error)
		helper.WriteJsonError(w, http.StatusInternalServerError, "user not found")
		return
	}

	// Generate new tokens
	accessTokenRaw, refreshTokenRaw, err := u.generateTokens(user.ID, user.Email)
	if err != nil {
		config.Config.Logger.Errorf("Token generation error: %v", err)
		helper.WriteJsonError(w, http.StatusInternalServerError, "token generation failed")
		return
	}

	// Set cookies
	u.setCookies(w, accessTokenRaw, refreshTokenRaw)

	helper.WriteJson(w, http.StatusOK, map[string]interface{}{
		"message": "tokens refreshed successfully",
	})
}

func (u *AuthHandler) logout(w http.ResponseWriter, r *http.Request) {
	refreshTokenFromCookie, err := r.Cookie("refresh_token")
	if err != nil {
		// Even if no cookie, clear cookies anyway
		u.clearCookies(w)
		helper.WriteJson(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
		return
	}

	token, err := jwt.Parse([]byte(refreshTokenFromCookie.Value),
		jwt.WithKey(jwa.HS256(), []byte(config.Config.RefreshTokenSecret)))
	if err != nil {
		// Token invalid, still clear cookies
		u.clearCookies(w)
		helper.WriteJson(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
		return
	}

	tokenIdStr, ok := token.Subject()
	if ok {
		// Convert string to uint for database query
		if tokenId, err := strconv.ParseUint(tokenIdStr, 10, 64); err == nil {
			// Delete refresh token from database
			u.db.Delete(&models.RefreshToken{}, tokenId)
		}
	}

	u.clearCookies(w)
	helper.WriteJson(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
}

// Helper function to generate both access and refresh tokens
func (u *AuthHandler) generateTokens(userID uint, email string) ([]byte, []byte, error) {
	// Load private key for access token
	set, err := jwk.ReadFile("certs/private.pem", jwk.WithPEM(true))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load private key: %w", err)
	}
	key, ok := set.Key(0)
	if !ok {
		return nil, nil, fmt.Errorf("private key not found at index 0")
	}

	// Generate access token
	userIDStr := strconv.FormatUint(uint64(userID), 10)
	accessToken, err := jwt.NewBuilder().
		Subject(userIDStr).
		Expiration(time.Now().Add(time.Hour*1)).
		Claim("email", email).
		Build()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build access token: %w", err)
	}

	accessTokenRaw, err := jwt.Sign(accessToken, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Create refresh token in database
	refreshTokenDB := models.RefreshToken{
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	}
	if err := u.db.Create(&refreshTokenDB).Error; err != nil {
		return nil, nil, fmt.Errorf("failed to create refresh token in database: %w", err)
	}

	// Generate refresh token JWT
	refreshTokenIDStr := strconv.FormatUint(uint64(refreshTokenDB.ID), 10)
	refreshToken, err := jwt.NewBuilder().
		Subject(refreshTokenIDStr).
		Expiration(time.Now().Add(time.Hour*24)).
		Claim("email", email).
		Build()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build refresh token: %w", err)
	}

	refreshTokenRaw, err := jwt.Sign(refreshToken, jwt.WithKey(jwa.HS256(), []byte(config.Config.RefreshTokenSecret)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return accessTokenRaw, refreshTokenRaw, nil
}

// Helper function to set cookies
func (u *AuthHandler) setCookies(w http.ResponseWriter, accessToken, refreshToken []byte) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    string(accessToken),
		Expires:  time.Now().Add(1 * time.Hour),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   false, // Set to true in production with HTTPS
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    string(refreshToken),
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   false, // Set to true in production with HTTPS
	})
}

// Helper function to clear cookies
func (u *AuthHandler) clearCookies(w http.ResponseWriter) {
	cookies := []string{"access_token", "refresh_token"}
	for _, cookieName := range cookies {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    "",
			Path:     "/",
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			HttpOnly: true,
		})
	}
}
