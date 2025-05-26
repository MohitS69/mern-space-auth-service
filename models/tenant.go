package models

import "gorm.io/gorm"

type Tenant struct {
	gorm.Model
	Email   string `json:"email"`
	Address string `json:"address"`
}
