package ginhttp

import (
	permissions "github.com/liftelimasd/permissions"
	"github.com/gin-gonic/gin"
)

// RegisterRoutes mounts all permission endpoints under the given RouterGroup.
//
// uf is a host-provided UserFinder implementation (username → userID).
// Apply your auth middleware to the group before calling this function.
//
// Example:
//
//	protected := router.Group("/permissions")
//	protected.Use(myAuthMiddleware())
//	ginhttp.RegisterRoutes(protected, permSvc, &myUserFinder{db: db})
func RegisterRoutes(group *gin.RouterGroup, svc *permissions.Service, uf UserFinder) {
	h := newHandler(svc, uf)

	// Permission types
	group.GET("/types", h.listTypes)
	group.POST("/types", h.createType)
	group.PUT("/types/:id", h.updateType)
	group.DELETE("/types/:id", h.deleteType)

	// Roles
	group.GET("/roles", h.listRoles)
	group.POST("/roles", h.createRole)
	group.PUT("/roles/:name", h.updateRole)
	group.DELETE("/roles/:name", h.deleteRole)
	group.GET("/roles/:name/permissions", h.listRolePermissions)
	group.PUT("/roles/:name/permissions", h.upsertRolePermissions)
	group.DELETE("/roles/:name/permissions/:key", h.deleteRolePermission)

	// User permissions
	group.GET("/users/:username", h.listUserPermissions)
	group.PUT("/users/:username", h.upsertUserPermissions)
	group.DELETE("/users/:username/:key", h.deleteUserPermission)
	group.POST("/users/:username/reset", h.resetUserPermissions)
	group.GET("/users/:username/resolved", h.resolvedPermissions)
}
