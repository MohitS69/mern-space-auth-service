package dto

type CreateTenantDTO struct {
	Email   string `validate:"email"`
	Address string `validate:"min=2,max=100"`
}
type UpdateTenantDTO struct {
	Email   string `validate:"omitempty,email"`
	Address string `validate:"omitempty,min=2,max=100"`
}
