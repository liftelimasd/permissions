package permissions

type Repository interface {
	// Applications
	ListApplications() ([]Application, error)
	GetApplication(key string) (*Application, error)
	CreateApplication(app *Application) error
	UpdateApplication(app *Application) error
	DeleteApplication(key string) error

	// Roles
	ListRoles() ([]Role, error)
	GetRole(name string) (*Role, error)
	CreateRole(role *Role) error
	UpdateRole(role *Role) error
	DeleteRole(name string) error

	// Permission types
	ListTypes() ([]PermissionType, error)
	ListTypesByApp(appKey string) ([]PermissionType, error)
	GetType(id int) (*PermissionType, error)
	GetTypeByKey(appKey, key string) (*PermissionType, error)
	CreateType(pt *PermissionType) error
	UpdateType(pt *PermissionType) error
	DeleteType(id int) error

	// Role permissions
	ListRolePermissions(roleNames []string) ([]RolePermission, error)
	ListRolePermissionsByRole(roleName string) ([]RolePermission, error)
	UpsertRolePermission(rp *RolePermission) error
	DeleteRolePermission(roleName string, permissionTypeID int) error

	// User permissions
	ListUserPermissions(userID int) ([]UserPermission, error)
	ListUserPermissionsByUserIDs(userIDs []int) ([]UserPermission, error)
	UpsertUserPermission(up *UserPermission) error
	DeleteUserPermission(userID, permissionTypeID int) error
	DeleteAllUserPermissions(userID int) error

	// Audit log
	InsertAuditLog(log *AuditLog) error
	ListAuditLogs(offset, limit int) ([]AuditLog, int, error)
}
