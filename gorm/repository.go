package permgorm

import (
	"time"

	permissions "github.com/liftelimasd/permissions/v2"
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

// --- Applications ---

func (r *repository) ListApplications() ([]permissions.Application, error) {
	var ms []ApplicationModel
	if err := r.db.Find(&ms).Error; err != nil {
		return nil, err
	}
	out := make([]permissions.Application, len(ms))
	for i, m := range ms {
		out[i] = appModelToDomain(m)
	}
	return out, nil
}

func (r *repository) GetApplication(key string) (*permissions.Application, error) {
	var m ApplicationModel
	if err := r.db.Where("`key` = ?", key).First(&m).Error; err != nil {
		return nil, err
	}
	app := appModelToDomain(m)
	return &app, nil
}

func (r *repository) CreateApplication(app *permissions.Application) error {
	m := appToModel(app)
	return r.db.Create(&m).Error
}

func (r *repository) UpdateApplication(app *permissions.Application) error {
	return r.db.Model(&ApplicationModel{}).
		Where("`key` = ?", app.Key).
		Updates(map[string]any{
			"name":        app.Name,
			"description": app.Description,
			"updated_at":  time.Now(),
		}).Error
}

func (r *repository) DeleteApplication(key string) error {
	return r.db.Where("`key` = ?", key).Delete(&ApplicationModel{}).Error
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

func (r *repository) GetTypeByKey(appKey, key string) (*permissions.PermissionType, error) {
	var m PermissionTypeModel
	if err := r.db.Where("application_key = ? AND `key` = ?", appKey, key).First(&m).Error; err != nil {
		return nil, err
	}
	pt := permTypeModelToDomain(m)
	return &pt, nil
}

func (r *repository) ListTypesByApp(appKey string) ([]permissions.PermissionType, error) {
	var ms []PermissionTypeModel
	if err := r.db.Where("application_key = ?", appKey).Find(&ms).Error; err != nil {
		return nil, err
	}
	out := make([]permissions.PermissionType, len(ms))
	for i, m := range ms {
		out[i] = permTypeModelToDomain(m)
	}
	return out, nil
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

func (r *repository) ListUserPermissionsByUserIDs(userIDs []int) ([]permissions.UserPermission, error) {
	if len(userIDs) == 0 {
		return nil, nil
	}
	var ms []UserPermissionModel
	if err := r.db.Where("user_id IN ?", userIDs).Find(&ms).Error; err != nil {
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

// --- Audit log ---

func (r *repository) InsertAuditLog(log *permissions.AuditLog) error {
	now := time.Now()
	var meta *string
	if log.Metadata != "" {
		m := log.Metadata
		meta = &m
	}
	m := AuditLogModel{
		ActorUserID:      log.ActorUserID,
		Action:           string(log.Action),
		TargetType:       string(log.TargetType),
		TargetID:         log.TargetID,
		PermissionTypeID: log.PermissionTypeID,
		OldValue:         log.OldValue,
		NewValue:         log.NewValue,
		Metadata:         meta,
		CreatedAt:        &now,
	}
	if err := r.db.Create(&m).Error; err != nil {
		return err
	}
	log.ID = m.ID
	log.CreatedAt = now.Unix()
	return nil
}

func (r *repository) ListAuditLogs(offset, limit int) ([]permissions.AuditLog, int, error) {
	var total int64
	if err := r.db.Model(&AuditLogModel{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var ms []AuditLogModel
	if err := r.db.Order("id DESC").Offset(offset).Limit(limit).Find(&ms).Error; err != nil {
		return nil, 0, err
	}
	out := make([]permissions.AuditLog, len(ms))
	for i, m := range ms {
		meta := ""
		if m.Metadata != nil {
			meta = *m.Metadata
		}
		var created int64
		if m.CreatedAt != nil {
			created = m.CreatedAt.Unix()
		}
		out[i] = permissions.AuditLog{
			ID:               m.ID,
			ActorUserID:      m.ActorUserID,
			Action:           permissions.AuditAction(m.Action),
			TargetType:       permissions.AuditTarget(m.TargetType),
			TargetID:         m.TargetID,
			PermissionTypeID: m.PermissionTypeID,
			OldValue:         m.OldValue,
			NewValue:         m.NewValue,
			Metadata:         meta,
			CreatedAt:        created,
		}
	}
	return out, int(total), nil
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
		ID:             m.ID,
		ApplicationKey: m.ApplicationKey,
		Key:            m.Key,
		Description:    desc,
		DefaultValue:   int(m.DefaultValue),
	}
}

func permTypeToModel(pt *permissions.PermissionType) PermissionTypeModel {
	now := time.Now()
	desc := pt.Description
	return PermissionTypeModel{
		ApplicationKey: pt.ApplicationKey,
		Key:            pt.Key,
		Description:    &desc,
		DefaultValue:   int8(pt.DefaultValue),
		CreatedAt:      &now,
		UpdatedAt:      &now,
	}
}

func appModelToDomain(m ApplicationModel) permissions.Application {
	desc := ""
	if m.Description != nil {
		desc = *m.Description
	}
	return permissions.Application{Key: m.Key, Name: m.Name, Description: desc}
}

func appToModel(a *permissions.Application) ApplicationModel {
	now := time.Now()
	desc := a.Description
	return ApplicationModel{
		Key:         a.Key,
		Name:        a.Name,
		Description: &desc,
		CreatedAt:   &now,
		UpdatedAt:   &now,
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
