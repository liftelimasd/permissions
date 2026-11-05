package ginhttp

import (
	"errors"
	"net/http"
	"strconv"

	permissions "github.com/liftelimasd/permissions/v2"
	"github.com/gin-gonic/gin"
)

// User is the minimal shape this package needs about a user. The host can
// back it with whatever table/columns it has — only ID + Username are read.
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

// UserDirectory is the host-provided adapter to the underlying users table.
// The package does NOT own a users table — it asks the host to resolve.
//
// Implementations typically wrap the host's existing users table (which can
// have any extra columns: email, password, companyId, etc.). Only id +
// username (or its equivalent column, e.g. "login") are exposed here.
type UserDirectory interface {
	FindByUsername(username string) (User, error)
	FindByID(id int) (User, error)
	List(offset, limit int) (users []User, total int, err error)
}

// ActorIDFromContext is called on every mutating endpoint to identify the
// user performing the action (for audit log). The host's auth middleware
// MUST place the authenticated user's ID into the gin context before the
// request reaches these handlers. If it returns ok=false, the handler
// responds with 401.
//
// Default key is "actorUserID" but the host can override at registration.
type ActorIDFromContext func(ctx *gin.Context) (id int, ok bool)

// DefaultActorIDFromContext reads "actorUserID" from the gin context.
func DefaultActorIDFromContext(ctx *gin.Context) (int, bool) {
	v, exists := ctx.Get("actorUserID")
	if !exists {
		return 0, false
	}
	id, ok := v.(int)
	return id, ok
}

type Handler struct {
	svc     *permissions.Service
	dir     UserDirectory
	actorFn ActorIDFromContext
}

func newHandler(svc *permissions.Service, dir UserDirectory, actorFn ActorIDFromContext) *Handler {
	if actorFn == nil {
		actorFn = DefaultActorIDFromContext
	}
	return &Handler{svc: svc, dir: dir, actorFn: actorFn}
}

func (h *Handler) resolveUserID(ctx *gin.Context, username string) (int, bool) {
	u, err := h.dir.FindByUsername(username)
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return 0, false
	}
	return u.ID, true
}

func (h *Handler) requireActor(ctx *gin.Context) (int, bool) {
	id, ok := h.actorFn(ctx)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthenticated"})
		return 0, false
	}
	return id, true
}

// listAuditLogs returns audit entries newest-first with pagination.
//
// Query params: ?offset=0&limit=50
func (h *Handler) listAuditLogs(ctx *gin.Context) {
	offset, _ := strconv.Atoi(ctx.DefaultQuery("offset", "0"))
	limit, _ := strconv.Atoi(ctx.DefaultQuery("limit", "50"))
	logs, total, err := h.svc.ListAuditLogs(offset, limit)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"logs": logs, "total": total, "offset": offset, "limit": limit})
}

// listUsers returns paginated users from the host directory.
//
// Query params: ?offset=0&limit=50
func (h *Handler) listUsers(ctx *gin.Context) {
	offset, _ := strconv.Atoi(ctx.DefaultQuery("offset", "0"))
	limit, _ := strconv.Atoi(ctx.DefaultQuery("limit", "50"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	users, total, err := h.dir.List(offset, limit)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"users": users, "total": total, "offset": offset, "limit": limit})
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
	case errors.Is(err, permissions.ErrApplicationNotFound):
		return http.StatusNotFound, err.Error()
	case errors.Is(err, permissions.ErrApplicationExists):
		return http.StatusConflict, err.Error()
	case errors.Is(err, permissions.ErrInvalidApplicationKey):
		return http.StatusBadRequest, err.Error()
	default:
		return http.StatusInternalServerError, err.Error()
	}
}

// --- Applications ---

func (h *Handler) listApplications(ctx *gin.Context) {
	apps, err := h.svc.ListApplications()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, apps)
}

func (h *Handler) createApplication(ctx *gin.Context) {
	actor, ok := h.requireActor(ctx)
	if !ok {
		return
	}
	var req CreateApplicationRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.CreateApplicationAudited(actor, &permissions.Application{
		Key:         req.Key,
		Name:        req.Name,
		Description: req.Description,
	}); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusCreated, gin.H{"message": "application created"})
}

func (h *Handler) updateApplication(ctx *gin.Context) {
	actor, ok := h.requireActor(ctx)
	if !ok {
		return
	}
	var req UpdateApplicationRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.UpdateApplicationAudited(actor, &permissions.Application{
		Key:         ctx.Param("app"),
		Name:        req.Name,
		Description: req.Description,
	}); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "application updated"})
}

func (h *Handler) deleteApplication(ctx *gin.Context) {
	actor, ok := h.requireActor(ctx)
	if !ok {
		return
	}
	if err := h.svc.DeleteApplicationAudited(actor, ctx.Param("app")); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "application deleted"})
}

// --- Permission types ---

func (h *Handler) listTypes(ctx *gin.Context) {
	if app := ctx.Param("app"); app != "" {
		types, err := h.svc.ListTypesByApp(app)
		if err != nil {
			code, msg := httpErr(err)
			ctx.JSON(code, gin.H{"error": msg})
			return
		}
		ctx.JSON(http.StatusOK, types)
		return
	}
	types, err := h.svc.ListTypes()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, types)
}

func (h *Handler) createType(ctx *gin.Context) {
	actor, ok := h.requireActor(ctx)
	if !ok {
		return
	}
	var req CreateTypeRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.CreateTypeAudited(actor, &permissions.PermissionType{
		ApplicationKey: ctx.Param("app"),
		Key:            req.Key,
		Description:    req.Description,
		DefaultValue:   req.DefaultValue,
	}); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusCreated, gin.H{"message": "permission type created"})
}

func (h *Handler) updateType(ctx *gin.Context) {
	actor, ok := h.requireActor(ctx)
	if !ok {
		return
	}
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
	if err := h.svc.UpdateTypeAudited(actor, &permissions.PermissionType{
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
	actor, ok := h.requireActor(ctx)
	if !ok {
		return
	}
	id, err := strconv.Atoi(ctx.Param("id"))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := h.svc.DeleteTypeAudited(actor, id); err != nil {
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
	actor, ok := h.requireActor(ctx)
	if !ok {
		return
	}
	var req CreateRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.CreateRoleAudited(actor, &permissions.Role{Name: req.Name, Description: req.Description}); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusCreated, gin.H{"message": "role created"})
}

func (h *Handler) updateRole(ctx *gin.Context) {
	actor, ok := h.requireActor(ctx)
	if !ok {
		return
	}
	var req UpdateRoleRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.svc.UpdateRoleAudited(actor, &permissions.Role{Name: ctx.Param("name"), Description: req.Description}); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "role updated"})
}

func (h *Handler) deleteRole(ctx *gin.Context) {
	actor, ok := h.requireActor(ctx)
	if !ok {
		return
	}
	if err := h.svc.DeleteRoleAudited(actor, ctx.Param("name")); err != nil {
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

// upsertRolePermissions accepts a nested map { appKey: { permKey: value } }
// so role permissions can be set across multiple applications in one call.
func (h *Handler) upsertRolePermissions(ctx *gin.Context) {
	actor, ok := h.requireActor(ctx)
	if !ok {
		return
	}
	name := ctx.Param("name")
	var req UpsertRolePermissionsRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	types, err := h.svc.ListTypes()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// (appKey, key) → PermissionType
	typeByAppKey := make(map[string]map[string]permissions.PermissionType)
	for _, t := range types {
		if typeByAppKey[t.ApplicationKey] == nil {
			typeByAppKey[t.ApplicationKey] = make(map[string]permissions.PermissionType)
		}
		typeByAppKey[t.ApplicationKey][t.Key] = t
	}
	for appKey, perms := range req.Permissions {
		appTypes, ok := typeByAppKey[appKey]
		if !ok {
			continue
		}
		for key, value := range perms {
			pt, ok := appTypes[key]
			if !ok {
				continue
			}
			if err := h.svc.UpsertRolePermissionAudited(actor, &permissions.RolePermission{
				RoleName:         name,
				PermissionTypeID: pt.ID,
				Value:            value,
			}); err != nil {
				code, msg := httpErr(err)
				ctx.JSON(code, gin.H{"error": msg})
				return
			}
		}
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "role permissions updated"})
}

// deleteRolePermission removes one permission by (app, key) from a role.
// Route: DELETE /roles/:name/permissions/:app/:key
func (h *Handler) deleteRolePermission(ctx *gin.Context) {
	actor, ok := h.requireActor(ctx)
	if !ok {
		return
	}
	pt, err := h.svc.GetTypeByKey(ctx.Param("app"), ctx.Param("key"))
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": permissions.ErrTypeNotFound.Error()})
		return
	}
	if err := h.svc.DeleteRolePermissionAudited(actor, ctx.Param("name"), pt.ID); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "role permission deleted"})
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
	actor, okA := h.requireActor(ctx)
	if !okA {
		return
	}
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
	typeByAppKey := make(map[string]map[string]permissions.PermissionType)
	for _, t := range types {
		if typeByAppKey[t.ApplicationKey] == nil {
			typeByAppKey[t.ApplicationKey] = make(map[string]permissions.PermissionType)
		}
		typeByAppKey[t.ApplicationKey][t.Key] = t
	}
	for appKey, perms := range req.Permissions {
		appTypes, ok := typeByAppKey[appKey]
		if !ok {
			continue
		}
		for key, value := range perms {
			pt, ok := appTypes[key]
			if !ok {
				continue
			}
			if err := h.svc.UpsertUserPermissionAudited(actor, &permissions.UserPermission{
				UserID:           userID,
				PermissionTypeID: pt.ID,
				Value:            value,
			}); err != nil {
				code, msg := httpErr(err)
				ctx.JSON(code, gin.H{"error": msg})
				return
			}
		}
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "user permissions updated"})
}

// Route: DELETE /users/:username/:app/:key
func (h *Handler) deleteUserPermission(ctx *gin.Context) {
	actor, okA := h.requireActor(ctx)
	if !okA {
		return
	}
	userID, ok := h.resolveUserID(ctx, ctx.Param("username"))
	if !ok {
		return
	}
	pt, err := h.svc.GetTypeByKey(ctx.Param("app"), ctx.Param("key"))
	if err != nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": permissions.ErrTypeNotFound.Error()})
		return
	}
	if err := h.svc.DeleteUserPermissionAudited(actor, userID, pt.ID); err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "user permission deleted"})
}

func (h *Handler) resetUserPermissions(ctx *gin.Context) {
	actor, okA := h.requireActor(ctx)
	if !okA {
		return
	}
	userID, ok := h.resolveUserID(ctx, ctx.Param("username"))
	if !ok {
		return
	}
	if err := h.svc.DeleteAllUserPermissionsAudited(actor, userID); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"message": "user permissions reset"})
}

// resolvedPermissions returns the resolved permission map for a user.
//
// Query params:
//
//	?app=<key>  → flat map for that single application.
//	?app=all    → nested map { appKey: { permKey: value } } across all apps.
//	(omitted)   → same as app=all, but consider requiring an explicit value
//	             at the host level for safety.
func (h *Handler) resolvedPermissions(ctx *gin.Context) {
	userID, ok := h.resolveUserID(ctx, ctx.Param("username"))
	if !ok {
		return
	}
	app := ctx.Query("app")
	if app == "" || app == "all" {
		perms, err := h.svc.ResolveAll(userID, nil)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		ctx.JSON(http.StatusOK, perms)
		return
	}
	perms, err := h.svc.Resolve(userID, nil, app)
	if err != nil {
		code, msg := httpErr(err)
		ctx.JSON(code, gin.H{"error": msg})
		return
	}
	ctx.JSON(http.StatusOK, perms)
}
