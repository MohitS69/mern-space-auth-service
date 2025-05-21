package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"go.uber.org/zap"
)

type AppConfig struct {
	ServerPort         string
	DSN                string
	Logger             *zap.SugaredLogger
	RefreshTokenSecret string
}

var Config AppConfig

func init() {
	godotenv.Load()
	Dsn := fmt.Sprintf("host=%v user=%v password=%v dbname=%v port=%v", os.Getenv("DB_HOST"), os.Getenv("DB_USER"), os.Getenv("DB_PASSWORD"), os.Getenv("DB_NAME"), os.Getenv("DB_PORT"))
	logger := zap.Must(zap.NewProduction()).Sugar()

	Config = AppConfig{
		ServerPort:         os.Getenv("PORT"),
		DSN:                Dsn,
		Logger:             logger,
		RefreshTokenSecret: os.Getenv("REFRESH_TOKEN_SECRET"),
	}
}
