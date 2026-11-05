package ginhttp

import (
	permissions "github.com/liftelimasd/permissions/v2"
	"github.com/gin-gonic/gin"
)

// RegisterRoutes mounts all permission endpoints under the given RouterGroup.
//
// dir     — host-provided directory used to look up users by username/id.
// actorFn — extracts the actor user ID from the request context for audit.
//
//	Pass nil to use DefaultActorIDFromContext (reads "actorUserID").
//	If the actor cannot be identified on a mutating endpoint, the handler
//	responds 401.
//
// Apply your auth middleware to the group before calling this function.
//
// Example:
//
//	protected := router.Group("/permissions")
//	protected.Use(myAuthMiddleware()) // must c.Set("actorUserID", userID)
//	ginhttp.RegisterRoutes(protected, permSvc, &myDirectory{db: db}, nil)
func RegisterRoutes(group *gin.RouterGroup, svc *permissions.Service, dir UserDirectory, actorFn ActorIDFromContext) {
	h := newHandler(svc, dir, actorFn)

	// Applications
	group.GET("/applications", h.listApplications)
	group.POST("/applications", h.createApplication)
	group.PUT("/applications/:app", h.updateApplication)
	group.DELETE("/applications/:app", h.deleteApplication)

	// Permission types (namespaced by application)
	group.GET("/types", h.listTypes) // all apps
	group.GET("/applications/:app/types", h.listTypes)
	group.POST("/applications/:app/types", h.createType)
	group.PUT("/types/:id", h.updateType)
	group.DELETE("/types/:id", h.deleteType)

	// Roles
	group.GET("/roles", h.listRoles)
	group.POST("/roles", h.createRole)
	group.PUT("/roles/:name", h.updateRole)
	group.DELETE("/roles/:name", h.deleteRole)
	group.GET("/roles/:name/permissions", h.listRolePermissions)
	group.PUT("/roles/:name/permissions", h.upsertRolePermissions)
	group.DELETE("/roles/:name/permissions/:app/:key", h.deleteRolePermission)

	// Users (directory)
	group.GET("/users", h.listUsers)

	// Audit log
	group.GET("/audit", h.listAuditLogs)

	// User permissions
	group.GET("/users/:username", h.listUserPermissions)
	group.PUT("/users/:username", h.upsertUserPermissions)
	group.DELETE("/users/:username/:app/:key", h.deleteUserPermission)
	group.POST("/users/:username/reset", h.resetUserPermissions)
	group.GET("/users/:username/resolved", h.resolvedPermissions)
}
