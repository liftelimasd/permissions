package permgorm

import (
	"time"

	permissions "github.com/liftelimasd/permissions"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type repository struct {
	db *gorm.DB
}

var _ permissions.Repository = (*repository)(nil)

// NewRepository returns a permissions.Repository backed by GORM.
// Pass your already-initialized *gorm.DB — this package never opens connections.
func NewRepository(db *gorm.DB) permissions.Repository {
	return &repository{db: db}
}

// --- Roles ---

func (r *repository) ListRoles() ([]permissions.Role, error) {
	var ms []RoleModel
	if err := r.db.Find(&ms).Error; err != nil {
		return nil, err
	}
	out := make([]permissions.Role, len(ms))
	for i, m := range ms {
		out[i] = roleModelToDomain(m)
	}
	return out, nil
}

func (r *repository) GetRole(name string) (*permissions.Role, error) {
	var m RoleModel
	if err := r.db.Where("name = ?", name).First(&m).Error; err != nil {
		return nil, err
	}
	role := roleModelToDomain(m)
	return &role, nil
}

func (r *repository) CreateRole(role *permissions.Role) error {
	m := roleToModel(role)
	return r.db.Create(&m).Error
}

func (r *repository) UpdateRole(role *permissions.Role) error {
	return r.db.Model(&RoleModel{}).
		Where("name = ?", role.Name).
		Updates(map[string]any{"description": role.Description, "updated_at": time.Now()}).Error
}

func (r *repository) DeleteRole(name string) error {
	return r.db.Where("name = ?", name).Delete(&RoleModel{}).Error
}

// --- Permission types ---

func (r *repository) ListTypes() ([]permissions.PermissionType, error) {
	var ms []PermissionTypeModel
	if err := r.db.Find(&ms).Error; err != nil {
		return nil, err
	}
	out := make([]permissions.PermissionType, len(ms))
	for i, m := range ms {
		out[i] = permTypeModelToDomain(m)
	}
	return out, nil
}

func (r *repository) GetType(id int) (*permissions.PermissionType, error) {
	var m PermissionTypeModel
	if err := r.db.Where("id = ?", id).First(&m).Error; err != nil {
		return nil, err
	}
	pt := permTypeModelToDomain(m)
	return &pt, nil
}

func (r *repository) GetTypeByKey(key string) (*permissions.PermissionType, error) {
	var m PermissionTypeModel
	if err := r.db.Where("`key` = ?", key).First(&m).Error; err != nil {
		return nil, err
	}
	pt := permTypeModelToDomain(m)
	return &pt, nil
}

func (r *repository) CreateType(pt *permissions.PermissionType) error {
	m := permTypeToModel(pt)
	return r.db.Create(&m).Error
}

func (r *repository) UpdateType(pt *permissions.PermissionType) error {
	return r.db.Model(&PermissionTypeModel{}).
		Where("id = ?", pt.ID).
		Updates(map[string]any{
			"description":   pt.Description,
			"default_value": pt.DefaultValue,
			"updated_at":    time.Now(),
		}).Error
}

func (r *repository) DeleteType(id int) error {
	return r.db.Where("id = ?", id).Delete(&PermissionTypeModel{}).Error
}

// --- Role permissions ---

func (r *repository) ListRolePermissions(roleNames []string) ([]permissions.RolePermission, error) {
	if len(roleNames) == 0 {
		return nil, nil
	}
	var ms []RolePermissionModel
	if err := r.db.Where("role_name IN ?", roleNames).Find(&ms).Error; err != nil {
		return nil, err
	}
	return rolePermModelsToDomain(ms), nil
}

func (r *repository) ListRolePermissionsByRole(roleName string) ([]permissions.RolePermission, error) {
	var ms []RolePermissionModel
	if err := r.db.Where("role_name = ?", roleName).Find(&ms).Error; err != nil {
		return nil, err
	}
	return rolePermModelsToDomain(ms), nil
}

func (r *repository) UpsertRolePermission(rp *permissions.RolePermission) error {
	now := time.Now()
	m := RolePermissionModel{
		RoleName:         rp.RoleName,
		PermissionTypeID: rp.PermissionTypeID,
		Value:            int8(rp.Value),
		CreatedAt:        &now,
		UpdatedAt:        &now,
	}
	return r.db.
		Where("role_name = ? AND permission_type_id = ?", rp.RoleName, rp.PermissionTypeID).
		Assign(RolePermissionModel{Value: int8(rp.Value), UpdatedAt: &now}).
		FirstOrCreate(&m).Error
}

func (r *repository) DeleteRolePermission(roleName string, permissionTypeID int) error {
	return r.db.
		Where("role_name = ? AND permission_type_id = ?", roleName, permissionTypeID).
		Delete(&RolePermissionModel{}).Error
}

// --- User permissions ---

func (r *repository) ListUserPermissions(userID int) ([]permissions.UserPermission, error) {
	var ms []UserPermissionModel
	if err := r.db.Where("user_id = ?", userID).Find(&ms).Error; err != nil {
		return nil, err
	}
	out := make([]permissions.UserPermission, len(ms))
	for i, m := range ms {
		out[i] = permissions.UserPermission{
			ID:               m.ID,
			UserID:           m.UserID,
			PermissionTypeID: m.PermissionTypeID,
			Value:            int(m.Value),
		}
	}
	return out, nil
}

func (r *repository) UpsertUserPermission(up *permissions.UserPermission) error {
	now := time.Now()
	m := UserPermissionModel{
		UserID:           up.UserID,
		PermissionTypeID: up.PermissionTypeID,
		Value:            int8(up.Value),
		CreatedAt:        &now,
		UpdatedAt:        &now,
	}
	return r.db.
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}, {Name: "permission_type_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
		}).
		Create(&m).Error
}

func (r *repository) DeleteUserPermission(userID, permissionTypeID int) error {
	return r.db.
		Where("user_id = ? AND permission_type_id = ?", userID, permissionTypeID).
		Delete(&UserPermissionModel{}).Error
}

func (r *repository) DeleteAllUserPermissions(userID int) error {
	return r.db.Where("user_id = ?", userID).Delete(&UserPermissionModel{}).Error
}

// --- mappers ---

func roleModelToDomain(m RoleModel) permissions.Role {
	desc := ""
	if m.Description != nil {
		desc = *m.Description
	}
	return permissions.Role{Name: m.Name, Description: desc}
}

func roleToModel(r *permissions.Role) RoleModel {
	now := time.Now()
	desc := r.Description
	return RoleModel{Name: r.Name, Description: &desc, CreatedAt: &now, UpdatedAt: &now}
}

func permTypeModelToDomain(m PermissionTypeModel) permissions.PermissionType {
	desc := ""
	if m.Description != nil {
		desc = *m.Description
	}
	return permissions.PermissionType{
		ID:           m.ID,
		Key:          m.Key,
		Description:  desc,
		DefaultValue: int(m.DefaultValue),
	}
}

func permTypeToModel(pt *permissions.PermissionType) PermissionTypeModel {
	now := time.Now()
	desc := pt.Description
	return PermissionTypeModel{
		Key:          pt.Key,
		Description:  &desc,
		DefaultValue: int8(pt.DefaultValue),
		CreatedAt:    &now,
		UpdatedAt:    &now,
	}
}

func rolePermModelsToDomain(ms []RolePermissionModel) []permissions.RolePermission {
	out := make([]permissions.RolePermission, len(ms))
	for i, m := range ms {
		out[i] = permissions.RolePermission{
			ID:               m.ID,
			RoleName:         m.RoleName,
			PermissionTypeID: m.PermissionTypeID,
			Value:            int(m.Value),
		}
	}
	return out
}
