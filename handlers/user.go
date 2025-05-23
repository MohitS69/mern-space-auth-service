package handlers

import (
	"auth-service/config"
	"auth-service/dto"
	"auth-service/helper"
	"auth-service/models"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
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
	mux.HandleFunc("GET /self", handler.self)
	mux.HandleFunc("GET /refresh", handler.refresh)
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
	var isExists models.User

	if err := u.db.Where("email = ?", payload.Email).Find(&isExists).Error; err == nil {
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

	file, err := os.ReadFile("certs/private.pem")
	if err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, err.Error())
		return
	}
	key, err := jwk.ParseKey(file, jwk.WithPEM(true))
	if err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, fmt.Sprintf("failed to parse key in PEM format: %s\n", err))
		return
	}

	accessToken, err := jwt.NewBuilder().Subject(string(user.ID)).Expiration(time.Now().Add(time.Hour*1)).Claim("email", user.Email).Build()
	if err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, err.Error())
		return
	}
	accessTokenRaw, err := jwt.Sign(accessToken, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, err.Error())
		return
	}
	refreshTokenDB := models.RefreshToken{
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	}
	if err := u.db.Create(&refreshTokenDB).Error; err != nil {
		helper.WriteJsonError(w, 400, err.Error())
		return
	}
	refreshToken, err := jwt.NewBuilder().Subject(string(refreshTokenDB.ID)).Expiration(time.Now().Add(time.Hour*24)).Claim("email", user.Email).Build()
	refreshTokenRaw, err := jwt.Sign(refreshToken, jwt.WithKey(jwa.HS256(), []byte(config.Config.RefreshTokenSecret)))
	if err != nil {
		helper.WriteJsonError(w, 400, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    string(refreshTokenRaw),
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    string(accessTokenRaw),
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})
	helper.WriteJson(w, 200, user)
}
func (u *UserHandler) login(w http.ResponseWriter, r *http.Request) {
	var payload dto.LoginUserDto
	if err := helper.ReadJson(w, r, &payload); err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, err.Error())
		return
	}
	if err := helper.Validator.Struct(payload); err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, err.Error())
		return
	}
	fmt.Println("value of logger", config.Config.Logger)
	config.Config.Logger.Debug("New request to login a user", zap.Any("payload", map[string]interface{}{
		"email": payload.Email,
	}))
	var user *models.User
	if err := u.db.Where("email =?", payload.Email).Find(&user).Error; err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, err.Error())
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(payload.Password)); err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, "Invalid credentials")
		return
	}
	file, err := os.ReadFile("certs/private.pem")
	if err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, err.Error())
		return
	}
	key, err := jwk.ParseKey(file, jwk.WithPEM(true))
	if err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, fmt.Sprintf("failed to parse key in PEM format: %s\n", err))
		return
	}

	accessToken, err := jwt.NewBuilder().Subject(string(user.ID)).Expiration(time.Now().Add(time.Hour*1)).Claim("email", user.Email).Build()
	if err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, err.Error())
		return
	}
	accessTokenRaw, err := jwt.Sign(accessToken, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		helper.WriteJsonError(w, http.StatusForbidden, err.Error())
		return
	}
	refreshTokenDB := models.RefreshToken{
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	}
	if err := u.db.Create(&refreshTokenDB).Error; err != nil {
		helper.WriteJsonError(w, 400, err.Error())
		return
	}
	refreshToken, err := jwt.NewBuilder().Subject(string(refreshTokenDB.ID)).Expiration(time.Now().Add(time.Hour*24)).Claim("email", user.Email).Build()
	refreshTokenRaw, err := jwt.Sign(refreshToken, jwt.WithKey(jwa.HS256(), []byte(config.Config.RefreshTokenSecret)))
	if err != nil {
		helper.WriteJsonError(w, 400, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    string(refreshTokenRaw),
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    string(accessTokenRaw),
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})
	helper.WriteJson(w, 200, user)
}
func (u *UserHandler) self(w http.ResponseWriter, r *http.Request) {

}
func (u *UserHandler) refresh(w http.ResponseWriter, r *http.Request) {

}
