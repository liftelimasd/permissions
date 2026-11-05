package permgorm

import "time"

type ApplicationModel struct {
	Key         string     `gorm:"primaryKey;size:50;column:key"`
	Name        string     `gorm:"size:100;not null;column:name"`
	Description *string    `gorm:"size:255;column:description"`
	CreatedAt   *time.Time `gorm:"type:datetime;column:created_at"`
	UpdatedAt   *time.Time `gorm:"type:datetime;column:updated_at"`
}

func (ApplicationModel) TableName() string { return "applications" }

type RoleModel struct {
	Name        string     `gorm:"primaryKey;size:100;column:name"`
	Description *string    `gorm:"size:255;column:description"`
	CreatedAt   *time.Time `gorm:"type:datetime;column:created_at"`
	UpdatedAt   *time.Time `gorm:"type:datetime;column:updated_at"`
}

func (RoleModel) TableName() string { return "roles" }

type PermissionTypeModel struct {
	ID             int              `gorm:"primaryKey;autoIncrement;column:id"`
	ApplicationKey string           `gorm:"size:50;not null;column:application_key;uniqueIndex:uq_app_key,priority:1"`
	Key            string           `gorm:"size:100;not null;column:key;uniqueIndex:uq_app_key,priority:2"`
	Description    *string          `gorm:"size:255;column:description"`
	DefaultValue   int8             `gorm:"not null;default:0;column:default_value"`
	CreatedAt      *time.Time       `gorm:"type:datetime;column:created_at"`
	UpdatedAt      *time.Time       `gorm:"type:datetime;column:updated_at"`
	Application    ApplicationModel `gorm:"foreignKey:ApplicationKey;references:Key;constraint:OnDelete:CASCADE,OnUpdate:CASCADE"`
}

func (PermissionTypeModel) TableName() string { return "permission_types" }

type RolePermissionModel struct {
	ID               int                 `gorm:"primaryKey;autoIncrement;column:id"`
	RoleName         string              `gorm:"size:100;not null;column:role_name;uniqueIndex:uq_role_perm,priority:1"`
	PermissionTypeID int                 `gorm:"not null;column:permission_type_id;uniqueIndex:uq_role_perm,priority:2"`
	Value            int8                `gorm:"not null;column:value"`
	CreatedAt        *time.Time          `gorm:"type:datetime;column:created_at"`
	UpdatedAt        *time.Time          `gorm:"type:datetime;column:updated_at"`
	Role             RoleModel           `gorm:"foreignKey:RoleName;references:Name;constraint:OnDelete:CASCADE,OnUpdate:CASCADE"`
	PermissionType   PermissionTypeModel `gorm:"foreignKey:PermissionTypeID;references:ID;constraint:OnDelete:CASCADE"`
}

func (RolePermissionModel) TableName() string { return "role_permissions" }

// UserPermissionModel has no FK to the host's users table intentionally.
// The host service can add that constraint in its own migration if needed.
type UserPermissionModel struct {
	ID               int                 `gorm:"primaryKey;autoIncrement;column:id"`
	UserID           int                 `gorm:"not null;column:user_id;uniqueIndex:uq_user_perm,priority:1"`
	PermissionTypeID int                 `gorm:"not null;column:permission_type_id;uniqueIndex:uq_user_perm,priority:2"`
	Value            int8                `gorm:"not null;column:value"`
	CreatedAt        *time.Time          `gorm:"type:datetime;column:created_at"`
	UpdatedAt        *time.Time          `gorm:"type:datetime;column:updated_at"`
	PermissionType   PermissionTypeModel `gorm:"foreignKey:PermissionTypeID;references:ID;constraint:OnDelete:CASCADE"`
}

func (UserPermissionModel) TableName() string { return "user_permissions" }

type AuditLogModel struct {
	ID               int        `gorm:"primaryKey;autoIncrement;column:id"`
	ActorUserID      int        `gorm:"not null;column:actor_user_id;index"`
	Action           string     `gorm:"size:32;not null;column:action;index"`
	TargetType       string     `gorm:"size:32;not null;column:target_type;index"`
	TargetID         string     `gorm:"size:100;not null;column:target_id;index"`
	PermissionTypeID *int       `gorm:"column:permission_type_id"`
	OldValue         *int       `gorm:"column:old_value"`
	NewValue         *int       `gorm:"column:new_value"`
	Metadata         *string    `gorm:"type:text;column:metadata"`
	CreatedAt        *time.Time `gorm:"type:datetime;column:created_at;index"`
}

func (AuditLogModel) TableName() string { return "permission_audit_log" }
