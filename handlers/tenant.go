package handlers

import (
	"auth-service/config"
	"auth-service/dto"
	"auth-service/helper"
	"auth-service/models"
	"net/http"
	"strconv"

	"gorm.io/gorm"
)

type TenantHandler struct {
	db *gorm.DB
}

func SetupTenantRoutes(db *gorm.DB) *http.ServeMux {
	mux := http.NewServeMux()
	handler := TenantHandler{
		db,
	}
	mux.HandleFunc("POST /", handler.create)
    return mux
}

func (t *TenantHandler) create(w http.ResponseWriter, r *http.Request) {
	var payload dto.CreateTenantDTO
	if err := helper.ReadJson(w, r, &payload); err != nil {
		helper.WriteJsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := helper.Validator.Struct(payload); err != nil {
		helper.WriteJsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	config.Config.Logger.Infof("New request to create tenant with email: %s", payload.Email)
	tenant := models.Tenant{
		Email:   payload.Email,
		Address: payload.Address,
	}
	result := t.db.Create(&tenant)
	if result.Error != nil {
		helper.WriteJsonError(w, http.StatusBadRequest, result.Error.Error())
	}
	helper.WriteJson(w, http.StatusOK, tenant)
}

func (t *TenantHandler) update(w http.ResponseWriter, r *http.Request) {
	var payload dto.UpdateTenantDTO
	if err := helper.ReadJson(w, r, payload); err != nil {
		helper.WriteJsonError(w, http.StatusUnprocessableEntity, err.Error())
	}
	if err := helper.Validator.Struct(payload); err != nil {
		helper.WriteJsonError(w, http.StatusUnprocessableEntity, err.Error())
	}
	result := t.db.Model(&models.Tenant{}).Where("id =?", r.PathValue("id")).Updates(map[string]interface{}{
		"email":   payload.Email,
		"address": payload.Address,
	})
	if result.Error != nil {
		helper.WriteJsonError(w, http.StatusBadRequest, result.Error.Error())
	}
	helper.WriteJson(w, http.StatusOK, "tenant updated")
}
func (t *TenantHandler) getAll(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	queryForSearch := q.Get("q")
	perPageStr := q.Get("per_page")
	currentPageStr := q.Get("current_page")

	perPage, err := strconv.Atoi(perPageStr)
	if err != nil || perPage <= 0 {
		perPage = 10 // default value
	}

	currentPage, err := strconv.Atoi(currentPageStr)
	if err != nil || currentPage <= 0 {
		currentPage = 1 // default value
	}

	offset := (currentPage - 1) * perPage

	var tenants []models.Tenant
	query := t.db.Model(&models.Tenant{})

	if queryForSearch != "" {
		// Use ILIKE for case-insensitive search (PostgreSQL) or LIKE (MySQL)
		query = query.Where("name ILIKE ? OR address ILIKE ?",
			"%"+queryForSearch+"%",
			"%"+queryForSearch+"%")
	}

	result := query.Limit(perPage).Offset(offset).Find(&tenants)
	if result.Error != nil {
		config.Config.Logger.Errorf("Database error fetching tenants: %v", result.Error)
		helper.WriteJsonError(w, http.StatusInternalServerError, "database error")
		return
	}

	var totalCount int64
	countQuery := t.db.Model(&models.Tenant{})
	if queryForSearch != "" {
		countQuery = countQuery.Where("name ILIKE ? OR address ILIKE ?",
			"%"+queryForSearch+"%",
			"%"+queryForSearch+"%")
	}
	countQuery.Count(&totalCount)

	// Prepare response
	response := map[string]interface{}{
		"data": tenants,
		"pagination": map[string]interface{}{
			"current_page": currentPage,
			"per_page":     perPage,
			"total":        totalCount,
			"total_pages":  (totalCount + int64(perPage) - 1) / int64(perPage),
		},
	}

	helper.WriteJson(w, http.StatusOK, response)
}

func (t *TenantHandler) getOne(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		helper.WriteJsonError(w, http.StatusBadRequest, "Id not provided in the path")
		return
	}
	var tenant models.Tenant
	result := t.db.Where("id =?", id).Find(&tenant)
	if result.Error != nil {
		helper.WriteJsonError(w, http.StatusBadRequest, result.Error.Error())
		return
	}
	helper.WriteJson(w, http.StatusOK, tenant)
}

func (t *TenantHandler) delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		helper.WriteJsonError(w, http.StatusBadRequest, "Id not provided in the path")
		return
	}
	var tenant models.Tenant
	result := t.db.Delete(&tenant, id)
	if result.Error != nil {
		helper.WriteJsonError(w, http.StatusBadRequest, result.Error.Error())
		return
	}
	helper.WriteJson(w, http.StatusOK, "tenant deleted successfully")
}
