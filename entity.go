package permissions

import "errors"

const (
	MinValue = 0
	MaxValue = 3
)

var (
	ErrRoleNotFound    = errors.New("role not found")
	ErrRoleExists      = errors.New("role already exists")
	ErrTypeNotFound    = errors.New("permission type not found")
	ErrTypeKeyExists   = errors.New("permission type key already exists")
	ErrInvalidValue    = errors.New("permission value must be between 0 and 3")
	ErrInvalidRoleName = errors.New("role name must match ^[a-zA-Z0-9_-]+$")
)

type Role struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type PermissionType struct {
	ID           int    `json:"id"`
	Key          string `json:"key"`
	Description  string `json:"description"`
	DefaultValue int    `json:"defaultValue"`
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
