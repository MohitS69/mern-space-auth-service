package handlers

import (
	"auth-service/config"
	"auth-service/dto"
	"auth-service/helper"
	"auth-service/models"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserHandler struct {
	db *gorm.DB
}

func SetupUserRoutes(mux *http.ServeMux, db *gorm.DB) {
	handler := UserHandler{
		db: db,
	}
	mux.HandleFunc("POST /register", handler.register)
	mux.HandleFunc("POST /login", handler.login)
}

func (u *UserHandler) register(w http.ResponseWriter, r *http.Request) {
	var payload dto.RegisterUserDto
	if err := helper.ReadJson(w, r, &payload); err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, err.Error())
		return
	}
	if err := helper.Validator.Struct(payload); err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, err.Error())
		return
	}

	config.Config.Logger.Debug("New Request to register a user", zap.Any("payload", map[string]interface{}{
		"firstName": payload.FirstName,
		"lastName":  payload.LastName,
		"email":     payload.Email,
	}))
	user := models.User{
		Email:     payload.Email,
		Password:  payload.Password,
		FirstName: payload.FirstName,
		LastName:  payload.LastName,
		Role:      payload.Role,
	}
	var isExists *models.User

	u.db.Where("email = ?", payload.Email).Find(isExists)
	if isExists != nil {
		helper.WriteJsonError(w, 400, "user already exist")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		helper.WriteJsonError(w, 400, err.Error())
		return
	}
	user.Password = string(hash)
	if err := u.db.Create(&user).Error; err != nil {
		helper.WriteJsonError(w, 400, err.Error())
		return
	}

	privKeyByte, err := os.ReadFile("certs/private.pem")
	if err != nil {
		helper.WriteJsonError(w, 400, err.Error())
		return
	}
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKeyByte)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,                           // any custom claim
		"exp":   time.Now().Add(time.Hour * 1).Unix(), // expiry
	})
	accessTokenString, err := accessToken.SignedString(privKey)
	refreshToken := models.RefreshToken{
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	}
	if err := u.db.Create(&refreshToken).Error; err != nil {
		helper.WriteJsonError(w, 400, err.Error())
		return
	}
	refreshJwt := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   refreshToken.ID,
		"email": user.Email,                            // any custom claim
		"exp":   time.Now().Add(time.Hour * 24).Unix(), // expiry
	})
	refreshTokenString, err := refreshJwt.SignedString([]byte(config.Config.RefreshTokenSecret))
	if err != nil {
		helper.WriteJsonError(w, 400, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshTokenString,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessTokenString,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})
	helper.WriteJson(w, 200, user)
}
func (u *UserHandler) login(w http.ResponseWriter, r *http.Request) {

}
