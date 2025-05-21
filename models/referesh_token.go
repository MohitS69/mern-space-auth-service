package models

import (
	"gorm.io/gorm"
)

type RefreshToken struct {
	gorm.Model
	ExpiresAt int64
	UserID    uint
	User      User
}
