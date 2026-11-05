package permissions

import "errors"

const (
	MinValue = 0
	MaxValue = 3
)

var (
	ErrRoleNotFound           = errors.New("role not found")
	ErrRoleExists             = errors.New("role already exists")
	ErrTypeNotFound           = errors.New("permission type not found")
	ErrTypeKeyExists          = errors.New("permission type key already exists")
	ErrInvalidValue           = errors.New("permission value must be between 0 and 3")
	ErrInvalidRoleName        = errors.New("role name must match ^[a-zA-Z0-9_-]+$")
	ErrApplicationNotFound    = errors.New("application not found")
	ErrApplicationExists      = errors.New("application already exists")
	ErrInvalidApplicationKey  = errors.New("application key must match ^[a-zA-Z0-9_-]+$")
)

type Application struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Role struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type PermissionType struct {
	ID             int    `json:"id"`
	ApplicationKey string `json:"applicationKey"`
	Key            string `json:"key"`
	Description    string `json:"description"`
	DefaultValue   int    `json:"defaultValue"`
}

type RolePermission struct {
	ID               int    `json:"id"`
	RoleName         string `json:"roleName"`
	PermissionTypeID int    `json:"permissionTypeId"`
	Value            int    `json:"value"`
}

type UserPermission struct {
	ID               int `json:"id"`
	UserID           int `json:"userId"`
	PermissionTypeID int `json:"permissionTypeId"`
	Value            int `json:"value"`
}

// AuditAction enumerates the kinds of mutations the audit log records.
type AuditAction string

const (
	AuditActionGrant     AuditAction = "grant"      // upsert role/user permission
	AuditActionRevoke    AuditAction = "revoke"     // delete role/user permission
	AuditActionCreate    AuditAction = "create"     // create role/type/application
	AuditActionUpdate    AuditAction = "update"     // update role/type/application
	AuditActionDelete    AuditAction = "delete"     // delete role/type/application
	AuditActionResetUser AuditAction = "reset_user" // delete all user perms
)

// AuditTarget identifies the kind of entity that was mutated.
type AuditTarget string

const (
	AuditTargetApplication AuditTarget = "application"
	AuditTargetRole        AuditTarget = "role"
	AuditTargetType        AuditTarget = "permission_type"
	AuditTargetUser        AuditTarget = "user"
)

type AuditLog struct {
	ID               int         `json:"id"`
	ActorUserID      int         `json:"actorUserId"`
	Action           AuditAction `json:"action"`
	TargetType       AuditTarget `json:"targetType"`
	TargetID         string      `json:"targetId"`          // role name / app key / "userID:typeID" / type ID
	PermissionTypeID *int        `json:"permissionTypeId,omitempty"`
	OldValue         *int        `json:"oldValue,omitempty"`
	NewValue         *int        `json:"newValue,omitempty"`
	Metadata         string      `json:"metadata,omitempty"`
	CreatedAt        int64       `json:"createdAt"` // unix seconds
}
