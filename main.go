package main

import (
	"auth-service/config"
	"auth-service/handlers"
	"auth-service/models"
	"fmt"
	"net/http"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	mux := http.NewServeMux()
	// Serve the "public" directory
	fs := http.FileServer(http.Dir("public"))

	mux.Handle("/", fs)
	db, err := gorm.Open(postgres.Open(config.Config.DSN), &gorm.Config{})

	defer config.Config.Logger.Sync()
	if err != nil {
		config.Config.Logger.Fatalf("database connection error %v\n", err)
	}
	config.Config.Logger.Info("database connected")
	err = db.AutoMigrate(&models.User{}, &models.RefreshToken{},&models.Tenant{})
	if err != nil {
		config.Config.Logger.Fatal("error while running migration :%v", err.Error())
	}
	config.Config.Logger.Info("migration was successfull")
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Api is healthy")
	})

    authRoutes := handlers.SetupAuthRoutes(db)
    tenantRoutes := handlers.SetupTenantRoutes(db)
    mux.Handle("/auth/",http.StripPrefix("/auth",authRoutes))
    mux.Handle("/tenants/",http.StripPrefix("/tenants",tenantRoutes))

	func() {
		config.Config.Logger.Infof("server is running on port %s", config.Config.ServerPort)
	}()
	http.ListenAndServe(fmt.Sprintf(":%s", config.Config.ServerPort), mux)
}
