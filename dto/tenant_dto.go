package dto

type CreateTenantDTO struct {
	Email   string `validate:"email"`
	Address string `validate:"string,min=2,max=100"`
}
type UpdateTenantDTO struct {
	Email   string `validate:"email"`
	Address string `validate:"string,min=2,max=100"`
}
