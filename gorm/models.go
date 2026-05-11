package permgorm

import "time"

type RoleModel struct {
	Name        string     `gorm:"primaryKey;size:100;column:name"`
	Description *string    `gorm:"size:255;column:description"`
	CreatedAt   *time.Time `gorm:"type:datetime;column:created_at"`
	UpdatedAt   *time.Time `gorm:"type:datetime;column:updated_at"`
}

func (RoleModel) TableName() string { return "roles" }

type PermissionTypeModel struct {
	ID           int        `gorm:"primaryKey;autoIncrement;column:id"`
	Key          string     `gorm:"uniqueIndex;size:100;not null;column:key"`
	Description  *string    `gorm:"size:255;column:description"`
	DefaultValue int8       `gorm:"not null;default:0;column:default_value"`
	CreatedAt    *time.Time `gorm:"type:datetime;column:created_at"`
	UpdatedAt    *time.Time `gorm:"type:datetime;column:updated_at"`
}

func (PermissionTypeModel) TableName() string { return "permission_types" }

type RolePermissionModel struct {
	ID               int        `gorm:"primaryKey;autoIncrement;column:id"`
	RoleName         string     `gorm:"size:100;not null;column:role_name;index"`
	PermissionTypeID int        `gorm:"not null;column:permission_type_id"`
	Value            int8       `gorm:"not null;column:value"`
	CreatedAt        *time.Time `gorm:"type:datetime;column:created_at"`
	UpdatedAt        *time.Time `gorm:"type:datetime;column:updated_at"`
	Role             RoleModel           `gorm:"foreignKey:RoleName;references:Name;constraint:OnDelete:CASCADE,OnUpdate:CASCADE"`
	PermissionType   PermissionTypeModel `gorm:"foreignKey:PermissionTypeID;references:ID;constraint:OnDelete:CASCADE"`
}

func (RolePermissionModel) TableName() string { return "role_permissions" }

// UserPermissionModel has no FK to the host's users table intentionally.
// The host service can add that constraint in its own migration if needed.
type UserPermissionModel struct {
	ID               int        `gorm:"primaryKey;autoIncrement;column:id"`
	UserID           int        `gorm:"not null;column:user_id;index"`
	PermissionTypeID int        `gorm:"not null;column:permission_type_id"`
	Value            int8       `gorm:"not null;column:value"`
	CreatedAt        *time.Time `gorm:"type:datetime;column:created_at"`
	UpdatedAt        *time.Time `gorm:"type:datetime;column:updated_at"`
	PermissionType   PermissionTypeModel `gorm:"foreignKey:PermissionTypeID;references:ID;constraint:OnDelete:CASCADE"`
}

func (UserPermissionModel) TableName() string { return "user_permissions" }
