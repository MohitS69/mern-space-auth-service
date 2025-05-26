package models

import "gorm.io/gorm"

type RoleType string

const (
	UserRole  RoleType = "user"
	AdminRole RoleType = "admin"
)

type User struct {
	gorm.Model
	FirstName string   `json:"first_name"`
	LastName  string   `json:"last_name"`
	Email     string   `json:"email"`
	Password  string   `json:"-"`
	Role      RoleType `json:"role"`
	TenantID  uint
	Tenant
}
