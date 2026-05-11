package ginhttp

import (
	"errors"
	"net/http"
	"strconv"

	permissions "github.com/liftelimasd/permissions"
	"github.com/gin-gonic/gin"
)

// UserFinder resolves a username string to the local user ID used in your
// service's database. Implement this with your own user repository.
//
// Example:
//
//	type myUserFinder struct{ db *gorm.DB }
//
//	func (f *myUserFinder) FindUserID(username string) (int, error) {
//	    var u struct{ ID int }
//	    return u.ID, f.db.Table("users").Select("id").
//	        Where("username = ?", username).First(&u).Error
//	}
type UserFinder interface {
	FindUserID(username string) (int, error)
}

type Handler struct {
	svc *permissions.Service
	uf  UserFinder
}

func newHandler(svc *permissions.Service, uf UserFinder) *Handler {
	return &Handler{svc: svc, uf: uf}
}

func (h *Handler) resolveUserID(ctx *gin.Context, username string) (int, bool) {
	id, err := h.uf.FindUserID(username)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return 0, false
	}
	return id, true
}

func httpErr(err error) (int, string) {
	switch {
	case errors.Is(err, permissions.ErrRoleNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, permissions.ErrRoleExists):
		return http.StatusConflict, err.Error()
	case errors.Is(err, permissions.ErrTypeNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, permissions.ErrTypeKeyExists):
		return http.StatusConflict, err.Error()
	case errors.Is(err, permissions.ErrInvalidValue):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, permissions.ErrInvalidRoleName):
		return http.StatusBadRequest, err.Error()
	default:
		return http.StatusInternalServerError, err.Error()
	}
}

// --- Permission types ---

func (h *Handler) listTypes(ctx *gin.Context) {
	types, err := h.svc.ListTypes()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, types)
}

func (h *Handler) createType(ctx *gin.Context) {
	var req CreateTypeRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.CreateType(&permissions.PermissionType{
		Key:          req.Key,
		Description:  req.Description,
		DefaultValue: req.DefaultValue,
	}); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusCreated, gin.H{"message": "permission type created"})
}

func (h *Handler) updateType(ctx *gin.Context) {
	id, err := strconv.Atoi(ctx.Param("id"))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req UpdateTypeRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.UpdateType(&permissions.PermissionType{
		ID:           id,
		Description:  req.Description,
		DefaultValue: req.DefaultValue,
	}); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "permission type updated"})
}

func (h *Handler) deleteType(ctx *gin.Context) {
	id, err := strconv.Atoi(ctx.Param("id"))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := h.svc.DeleteType(id); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "permission type deleted"})
}

// --- Roles ---

func (h *Handler) listRoles(ctx *gin.Context) {
	roles, err := h.svc.ListRoles()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, roles)
}

func (h *Handler) createRole(ctx *gin.Context) {
	var req CreateRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.CreateRole(&permissions.Role{Name: req.Name, Description: req.Description}); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusCreated, gin.H{"message": "role created"})
}

func (h *Handler) updateRole(ctx *gin.Context) {
	var req UpdateRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.UpdateRole(&permissions.Role{Name: ctx.Param("name"), Description: req.Description}); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "role updated"})
}

func (h *Handler) deleteRole(ctx *gin.Context) {
	if err := h.svc.DeleteRole(ctx.Param("name")); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "role deleted"})
}

// --- Role permissions ---

func (h *Handler) listRolePermissions(ctx *gin.Context) {
	perms, err := h.svc.ListRolePermissionsByRole(ctx.Param("name"))
	if err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusOK, perms)
}

func (h *Handler) upsertRolePermissions(ctx *gin.Context) {
	name := ctx.Param("name")
	var req UpsertPermissionsRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	types, err := h.svc.ListTypes()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	typeByKey := make(map[string]permissions.PermissionType, len(types))
	for _, t := range types {
		typeByKey[t.Key] = t
	}
	for key, value := range req.Permissions {
		pt, ok := typeByKey[key]
		if !ok {
			continue
		}
		if err := h.svc.UpsertRolePermission(&permissions.RolePermission{
			RoleName:         name,
			PermissionTypeID: pt.ID,
			Value:            value,
		}); err != nil {
			code, msg := httpErr(err)
			ctx.JSON(code, gin.H{"error": msg})
			return
		}
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "role permissions updated"})
}

func (h *Handler) deleteRolePermission(ctx *gin.Context) {
	types, err := h.svc.ListTypes()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for _, t := range types {
		if t.Key == ctx.Param("key") {
			if err := h.svc.DeleteRolePermission(ctx.Param("name"), t.ID); err != nil {
				code, msg := httpErr(err)
				ctx.JSON(code, gin.H{"error": msg})
				return
			}
			ctx.JSON(http.StatusOK, gin.H{"message": "role permission deleted"})
			return
		}
	}
	ctx.JSON(http.StatusNotFound, gin.H{"error": permissions.ErrTypeNotFound.Error()})
}

// --- User permissions ---

func (h *Handler) listUserPermissions(ctx *gin.Context) {
	userID, ok := h.resolveUserID(ctx, ctx.Param("username"))
	if !ok {
		return
	}
	perms, err := h.svc.ListUserPermissions(userID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, perms)
}

func (h *Handler) upsertUserPermissions(ctx *gin.Context) {
	userID, ok := h.resolveUserID(ctx, ctx.Param("username"))
	if !ok {
		return
	}
	var req UpsertPermissionsRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	types, err := h.svc.ListTypes()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	typeByKey := make(map[string]permissions.PermissionType, len(types))
	for _, t := range types {
		typeByKey[t.Key] = t
	}
	for key, value := range req.Permissions {
		pt, ok := typeByKey[key]
		if !ok {
			continue
		}
		if err := h.svc.UpsertUserPermission(&permissions.UserPermission{
			UserID:           userID,
			PermissionTypeID: pt.ID,
			Value:            value,
		}); err != nil {
			code, msg := httpErr(err)
			ctx.JSON(code, gin.H{"error": msg})
			return
		}
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "user permissions updated"})
}

func (h *Handler) deleteUserPermission(ctx *gin.Context) {
	userID, ok := h.resolveUserID(ctx, ctx.Param("username"))
	if !ok {
		return
	}
	types, err := h.svc.ListTypes()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for _, t := range types {
		if t.Key == ctx.Param("key") {
			if err := h.svc.DeleteUserPermission(userID, t.ID); err != nil {
				code, msg := httpErr(err)
				ctx.JSON(code, gin.H{"error": msg})
				return
			}
			ctx.JSON(http.StatusOK, gin.H{"message": "user permission deleted"})
			return
		}
	}
	ctx.JSON(http.StatusNotFound, gin.H{"error": permissions.ErrTypeNotFound.Error()})
}

func (h *Handler) resetUserPermissions(ctx *gin.Context) {
	userID, ok := h.resolveUserID(ctx, ctx.Param("username"))
	if !ok {
		return
	}
	if err := h.svc.DeleteAllUserPermissions(userID); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "user permissions reset"})
}

func (h *Handler) resolvedPermissions(ctx *gin.Context) {
	userID, ok := h.resolveUserID(ctx, ctx.Param("username"))
	if !ok {
		return
	}
	perms, err := h.svc.Resolve(userID, nil)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, perms)
}
