package permissions

import (
	"regexp"
	"strconv"
)

var (
	roleNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	appKeyRegex   = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	// Type keys may use dots to group related permissions (screens.config).
	typeKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
)

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

// Atomic runs fn with a Service bound to a single transaction when the
// repository implements TxRepository: if fn returns an error, nothing it did
// is kept. With a plain Repository, fn runs without a transaction.
func (s *Service) Atomic(fn func(*Service) error) error {
	txRepo, ok := s.repo.(TxRepository)
	if !ok {
		return fn(s)
	}
	return txRepo.WithTx(func(r Repository) error {
		return fn(NewService(r))
	})
}

// Resolve builds the final permissions map for a user in a single application.
//
// Resolution order:
//  1. Seed with default_value of every permission_type in the application.
//  2. For each role the user has, apply its role_permissions — highest value wins
//     when a permission appears in multiple roles.
//  3. Apply user_permissions unconditionally — user overrides always win,
//     even if the value is lower than the role-level value.
//
// Returns ErrApplicationNotFound if appKey does not exist.
func (s *Service) Resolve(userID int, roleNames []string, appKey string) (map[string]int, error) {
	if _, err := s.repo.GetApplication(appKey); err != nil {
		return nil, ErrApplicationNotFound
	}
	types, err := s.repo.ListTypesByApp(appKey)
	if err != nil {
		return nil, err
	}
	if len(types) == 0 {
		return map[string]int{}, nil
	}

	result := make(map[string]int, len(types))
	typeByID := make(map[int]string, len(types))
	for _, t := range types {
		result[t.Key] = t.DefaultValue
		typeByID[t.ID] = t.Key
	}

	if len(roleNames) > 0 {
		rolePerms, err := s.repo.ListRolePermissions(roleNames)
		if err != nil {
			return nil, err
		}
		for _, rp := range rolePerms {
			key, ok := typeByID[rp.PermissionTypeID]
			if !ok {
				continue
			}
			if rp.Value > result[key] {
				result[key] = rp.Value
			}
		}
	}

	userPerms, err := s.repo.ListUserPermissions(userID)
	if err != nil {
		return nil, err
	}
	for _, up := range userPerms {
		key, ok := typeByID[up.PermissionTypeID]
		if !ok {
			continue
		}
		result[key] = up.Value
	}

	return result, nil
}

// ResolveAll builds the resolved permissions for a user across every
// registered application, grouped by application key.
//
// Use this for admin panels / permission managers that need a full view.
// For per-app logins, use Resolve(userID, roles, appKey) instead — it
// returns a flat map and is cheaper.
func (s *Service) ResolveAll(userID int, roleNames []string) (map[string]map[string]int, error) {
	types, err := s.repo.ListTypes()
	if err != nil {
		return nil, err
	}
	result := make(map[string]map[string]int)
	if len(types) == 0 {
		return result, nil
	}

	type typeMeta struct {
		appKey string
		key    string
	}
	typeByID := make(map[int]typeMeta, len(types))
	for _, t := range types {
		if result[t.ApplicationKey] == nil {
			result[t.ApplicationKey] = make(map[string]int)
		}
		result[t.ApplicationKey][t.Key] = t.DefaultValue
		typeByID[t.ID] = typeMeta{appKey: t.ApplicationKey, key: t.Key}
	}

	if len(roleNames) > 0 {
		rolePerms, err := s.repo.ListRolePermissions(roleNames)
		if err != nil {
			return nil, err
		}
		for _, rp := range rolePerms {
			m, ok := typeByID[rp.PermissionTypeID]
			if !ok {
				continue
			}
			if rp.Value > result[m.appKey][m.key] {
				result[m.appKey][m.key] = rp.Value
			}
		}
	}

	userPerms, err := s.repo.ListUserPermissions(userID)
	if err != nil {
		return nil, err
	}
	for _, up := range userPerms {
		m, ok := typeByID[up.PermissionTypeID]
		if !ok {
			continue
		}
		result[m.appKey][m.key] = up.Value
	}

	return result, nil
}

// UserRoles is the input pair for ResolveBatch.
type UserRoles struct {
	UserID int
	Roles  []string
}

// ResolveBatch resolves permissions for many users in a single application,
// in 3 queries total independent of the number of users.
//
// Returns ErrApplicationNotFound if appKey does not exist.
func (s *Service) ResolveBatch(users []UserRoles, appKey string) (map[int]map[string]int, error) {
	result := make(map[int]map[string]int, len(users))
	if len(users) == 0 {
		return result, nil
	}
	if _, err := s.repo.GetApplication(appKey); err != nil {
		return nil, ErrApplicationNotFound
	}

	types, err := s.repo.ListTypesByApp(appKey)
	if err != nil {
		return nil, err
	}
	if len(types) == 0 {
		return result, nil
	}

	defaults := make(map[string]int, len(types))
	typeByID := make(map[int]string, len(types))
	for _, t := range types {
		defaults[t.Key] = t.DefaultValue
		typeByID[t.ID] = t.Key
	}

	roleSet := make(map[string]struct{})
	userIDs := make([]int, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.UserID)
		for _, r := range u.Roles {
			roleSet[r] = struct{}{}
		}
	}
	roleNames := make([]string, 0, len(roleSet))
	for r := range roleSet {
		roleNames = append(roleNames, r)
	}

	rolePerms, err := s.repo.ListRolePermissions(roleNames)
	if err != nil {
		return nil, err
	}
	rolePermsByRole := make(map[string]map[string]int)
	for _, rp := range rolePerms {
		key, ok := typeByID[rp.PermissionTypeID]
		if !ok {
			continue
		}
		if rolePermsByRole[rp.RoleName] == nil {
			rolePermsByRole[rp.RoleName] = make(map[string]int)
		}
		rolePermsByRole[rp.RoleName][key] = rp.Value
	}

	userPerms, err := s.repo.ListUserPermissionsByUserIDs(userIDs)
	if err != nil {
		return nil, err
	}
	userPermsByID := make(map[int]map[string]int)
	for _, up := range userPerms {
		key, ok := typeByID[up.PermissionTypeID]
		if !ok {
			continue
		}
		if userPermsByID[up.UserID] == nil {
			userPermsByID[up.UserID] = make(map[string]int)
		}
		userPermsByID[up.UserID][key] = up.Value
	}

	for _, u := range users {
		m := make(map[string]int, len(defaults))
		for k, v := range defaults {
			m[k] = v
		}
		for _, roleName := range u.Roles {
			if rp, ok := rolePermsByRole[roleName]; ok {
				for k, v := range rp {
					if v > m[k] {
						m[k] = v
					}
				}
			}
		}
		if up, ok := userPermsByID[u.UserID]; ok {
			for k, v := range up {
				m[k] = v
			}
		}
		result[u.UserID] = m
	}

	return result, nil
}

// ResolveAllBatch resolves permissions for many users across all applications.
// Returns nested maps: userID → appKey → permission key → value.
//
// Same 3-query guarantee as ResolveBatch.
func (s *Service) ResolveAllBatch(users []UserRoles) (map[int]map[string]map[string]int, error) {
	result := make(map[int]map[string]map[string]int, len(users))
	if len(users) == 0 {
		return result, nil
	}

	types, err := s.repo.ListTypes()
	if err != nil {
		return nil, err
	}
	if len(types) == 0 {
		return result, nil
	}

	type typeMeta struct {
		appKey string
		key    string
	}
	defaults := make(map[string]map[string]int)
	typeByID := make(map[int]typeMeta, len(types))
	for _, t := range types {
		if defaults[t.ApplicationKey] == nil {
			defaults[t.ApplicationKey] = make(map[string]int)
		}
		defaults[t.ApplicationKey][t.Key] = t.DefaultValue
		typeByID[t.ID] = typeMeta{appKey: t.ApplicationKey, key: t.Key}
	}

	roleSet := make(map[string]struct{})
	userIDs := make([]int, 0, len(users))
	for _, u := range users {
		userIDs = append(userIDs, u.UserID)
		for _, r := range u.Roles {
			roleSet[r] = struct{}{}
		}
	}
	roleNames := make([]string, 0, len(roleSet))
	for r := range roleSet {
		roleNames = append(roleNames, r)
	}

	rolePerms, err := s.repo.ListRolePermissions(roleNames)
	if err != nil {
		return nil, err
	}
	// roleName → appKey → key → value
	rolePermsByRole := make(map[string]map[string]map[string]int)
	for _, rp := range rolePerms {
		m, ok := typeByID[rp.PermissionTypeID]
		if !ok {
			continue
		}
		if rolePermsByRole[rp.RoleName] == nil {
			rolePermsByRole[rp.RoleName] = make(map[string]map[string]int)
		}
		if rolePermsByRole[rp.RoleName][m.appKey] == nil {
			rolePermsByRole[rp.RoleName][m.appKey] = make(map[string]int)
		}
		rolePermsByRole[rp.RoleName][m.appKey][m.key] = rp.Value
	}

	userPerms, err := s.repo.ListUserPermissionsByUserIDs(userIDs)
	if err != nil {
		return nil, err
	}
	userPermsByID := make(map[int]map[string]map[string]int)
	for _, up := range userPerms {
		m, ok := typeByID[up.PermissionTypeID]
		if !ok {
			continue
		}
		if userPermsByID[up.UserID] == nil {
			userPermsByID[up.UserID] = make(map[string]map[string]int)
		}
		if userPermsByID[up.UserID][m.appKey] == nil {
			userPermsByID[up.UserID][m.appKey] = make(map[string]int)
		}
		userPermsByID[up.UserID][m.appKey][m.key] = up.Value
	}

	for _, u := range users {
		byApp := make(map[string]map[string]int, len(defaults))
		for appKey, perms := range defaults {
			m := make(map[string]int, len(perms))
			for k, v := range perms {
				m[k] = v
			}
			byApp[appKey] = m
		}
		for _, roleName := range u.Roles {
			if rp, ok := rolePermsByRole[roleName]; ok {
				for appKey, perms := range rp {
					if byApp[appKey] == nil {
						byApp[appKey] = make(map[string]int)
					}
					for k, v := range perms {
						if v > byApp[appKey][k] {
							byApp[appKey][k] = v
						}
					}
				}
			}
		}
		if up, ok := userPermsByID[u.UserID]; ok {
			for appKey, perms := range up {
				if byApp[appKey] == nil {
					byApp[appKey] = make(map[string]int)
				}
				for k, v := range perms {
					byApp[appKey][k] = v
				}
			}
		}
		result[u.UserID] = byApp
	}

	return result, nil
}

// --- Roles ---

func (s *Service) ListRoles() ([]Role, error)         { return s.repo.ListRoles() }
func (s *Service) GetRole(name string) (*Role, error) { return s.repo.GetRole(name) }

func (s *Service) CreateRole(role *Role) error {
	if !roleNameRegex.MatchString(role.Name) {
		return ErrInvalidRoleName
	}
	if _, err := s.repo.GetRole(role.Name); err == nil {
		return ErrRoleExists
	}
	return s.repo.CreateRole(role)
}

func (s *Service) UpdateRole(role *Role) error {
	if _, err := s.repo.GetRole(role.Name); err != nil {
		return ErrRoleNotFound
	}
	return s.repo.UpdateRole(role)
}

func (s *Service) DeleteRole(name string) error {
	if _, err := s.repo.GetRole(name); err != nil {
		return ErrRoleNotFound
	}
	return s.repo.DeleteRole(name)
}

// --- Applications ---

func (s *Service) ListApplications() ([]Application, error) { return s.repo.ListApplications() }
func (s *Service) GetApplication(key string) (*Application, error) {
	app, err := s.repo.GetApplication(key)
	if err != nil {
		return nil, ErrApplicationNotFound
	}
	return app, nil
}

func (s *Service) CreateApplication(app *Application) error {
	if !appKeyRegex.MatchString(app.Key) {
		return ErrInvalidApplicationKey
	}
	if _, err := s.repo.GetApplication(app.Key); err == nil {
		return ErrApplicationExists
	}
	return s.repo.CreateApplication(app)
}

func (s *Service) UpdateApplication(app *Application) error {
	if _, err := s.repo.GetApplication(app.Key); err != nil {
		return ErrApplicationNotFound
	}
	return s.repo.UpdateApplication(app)
}

func (s *Service) DeleteApplication(key string) error {
	if _, err := s.repo.GetApplication(key); err != nil {
		return ErrApplicationNotFound
	}
	return s.repo.DeleteApplication(key)
}

// --- Permission types ---

func (s *Service) ListTypes() ([]PermissionType, error) { return s.repo.ListTypes() }

func (s *Service) ListTypesByApp(appKey string) ([]PermissionType, error) {
	if _, err := s.repo.GetApplication(appKey); err != nil {
		return nil, ErrApplicationNotFound
	}
	return s.repo.ListTypesByApp(appKey)
}

func (s *Service) GetType(id int) (*PermissionType, error) {
	pt, err := s.repo.GetType(id)
	if err != nil {
		return nil, ErrTypeNotFound
	}
	return pt, nil
}

func (s *Service) GetTypeByKey(appKey, key string) (*PermissionType, error) {
	pt, err := s.repo.GetTypeByKey(appKey, key)
	if err != nil {
		return nil, ErrTypeNotFound
	}
	return pt, nil
}

func (s *Service) CreateType(pt *PermissionType) error {
	if !typeKeyRegex.MatchString(pt.Key) {
		return ErrInvalidTypeKey
	}
	if err := validateValue(pt.DefaultValue); err != nil {
		return err
	}
	if _, err := s.repo.GetApplication(pt.ApplicationKey); err != nil {
		return ErrApplicationNotFound
	}
	if _, err := s.repo.GetTypeByKey(pt.ApplicationKey, pt.Key); err == nil {
		return ErrTypeKeyExists
	}
	return s.repo.CreateType(pt)
}

func (s *Service) UpdateType(pt *PermissionType) error {
	if _, err := s.repo.GetType(pt.ID); err != nil {
		return ErrTypeNotFound
	}
	if err := validateValue(pt.DefaultValue); err != nil {
		return err
	}
	return s.repo.UpdateType(pt)
}

func (s *Service) DeleteType(id int) error {
	if _, err := s.repo.GetType(id); err != nil {
		return ErrTypeNotFound
	}
	return s.repo.DeleteType(id)
}

// --- Role permissions ---

func (s *Service) ListRolePermissionsByRole(roleName string) ([]RolePermission, error) {
	if _, err := s.repo.GetRole(roleName); err != nil {
		return nil, ErrRoleNotFound
	}
	return s.repo.ListRolePermissionsByRole(roleName)
}

func (s *Service) UpsertRolePermission(rp *RolePermission) error {
	if _, err := s.repo.GetRole(rp.RoleName); err != nil {
		return ErrRoleNotFound
	}
	if _, err := s.repo.GetType(rp.PermissionTypeID); err != nil {
		return ErrTypeNotFound
	}
	if err := validateValue(rp.Value); err != nil {
		return err
	}
	return s.repo.UpsertRolePermission(rp)
}

func (s *Service) DeleteRolePermission(roleName string, permissionTypeID int) error {
	return s.repo.DeleteRolePermission(roleName, permissionTypeID)
}

// --- User permissions ---

func (s *Service) ListUserPermissions(userID int) ([]UserPermission, error) {
	return s.repo.ListUserPermissions(userID)
}

func (s *Service) UpsertUserPermission(up *UserPermission) error {
	if _, err := s.repo.GetType(up.PermissionTypeID); err != nil {
		return ErrTypeNotFound
	}
	if err := validateValue(up.Value); err != nil {
		return err
	}
	return s.repo.UpsertUserPermission(up)
}

func (s *Service) DeleteUserPermission(userID, permissionTypeID int) error {
	return s.repo.DeleteUserPermission(userID, permissionTypeID)
}

func (s *Service) DeleteAllUserPermissions(userID int) error {
	return s.repo.DeleteAllUserPermissions(userID)
}

func validateValue(v int) error {
	if v < MinValue || v > MaxValue {
		return ErrInvalidValue
	}
	return nil
}

// --- Audit log ---

// audit writes a single audit log row. Errors are swallowed: audit failures
// must never block the operation. The audit fields are best-effort.
func (s *Service) audit(actorUserID int, action AuditAction, target AuditTarget, targetID string, permTypeID *int, oldVal, newVal *int, metadata string) {
	_ = s.repo.InsertAuditLog(&AuditLog{
		ActorUserID:      actorUserID,
		Action:           action,
		TargetType:       target,
		TargetID:         targetID,
		PermissionTypeID: permTypeID,
		OldValue:         oldVal,
		NewValue:         newVal,
		Metadata:         metadata,
	})
}

// ListAuditLogs returns audit entries newest-first with pagination.
func (s *Service) ListAuditLogs(offset, limit int) ([]AuditLog, int, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return s.repo.ListAuditLogs(offset, limit)
}

// --- Audited mutations ---
//
// These wrap the non-audited methods and write a trail. Handlers should
// prefer the audited variants; the raw ones remain for programmatic use
// (seeds, migrations, tests) where no actor exists.

func (s *Service) CreateApplicationAudited(actorID int, app *Application) error {
	if err := s.CreateApplication(app); err != nil {
		return err
	}
	s.audit(actorID, AuditActionCreate, AuditTargetApplication, app.Key, nil, nil, nil, "")
	return nil
}

func (s *Service) UpdateApplicationAudited(actorID int, app *Application) error {
	if err := s.UpdateApplication(app); err != nil {
		return err
	}
	s.audit(actorID, AuditActionUpdate, AuditTargetApplication, app.Key, nil, nil, nil, "")
	return nil
}

func (s *Service) DeleteApplicationAudited(actorID int, key string) error {
	if err := s.DeleteApplication(key); err != nil {
		return err
	}
	s.audit(actorID, AuditActionDelete, AuditTargetApplication, key, nil, nil, nil, "")
	return nil
}

func (s *Service) CreateRoleAudited(actorID int, role *Role) error {
	if err := s.CreateRole(role); err != nil {
		return err
	}
	s.audit(actorID, AuditActionCreate, AuditTargetRole, role.Name, nil, nil, nil, "")
	return nil
}

func (s *Service) UpdateRoleAudited(actorID int, role *Role) error {
	if err := s.UpdateRole(role); err != nil {
		return err
	}
	s.audit(actorID, AuditActionUpdate, AuditTargetRole, role.Name, nil, nil, nil, "")
	return nil
}

func (s *Service) DeleteRoleAudited(actorID int, name string) error {
	if err := s.DeleteRole(name); err != nil {
		return err
	}
	s.audit(actorID, AuditActionDelete, AuditTargetRole, name, nil, nil, nil, "")
	return nil
}

func (s *Service) CreateTypeAudited(actorID int, pt *PermissionType) error {
	if err := s.CreateType(pt); err != nil {
		return err
	}
	s.audit(actorID, AuditActionCreate, AuditTargetType, pt.ApplicationKey+":"+pt.Key, &pt.ID, nil, nil, "")
	return nil
}

func (s *Service) UpdateTypeAudited(actorID int, pt *PermissionType) error {
	if err := s.UpdateType(pt); err != nil {
		return err
	}
	id := pt.ID
	s.audit(actorID, AuditActionUpdate, AuditTargetType, s.typeTargetID(id), &id, nil, nil, "")
	return nil
}

func (s *Service) DeleteTypeAudited(actorID int, id int) error {
	target := s.typeTargetID(id) // read before the type disappears
	if err := s.DeleteType(id); err != nil {
		return err
	}
	tid := id
	s.audit(actorID, AuditActionDelete, AuditTargetType, target, &tid, nil, nil, "")
	return nil
}

// typeTargetID returns "app:key" for the audit trail, or "" if the type is unknown.
func (s *Service) typeTargetID(id int) string {
	pt, err := s.repo.GetType(id)
	if err != nil {
		return ""
	}
	return pt.ApplicationKey + ":" + pt.Key
}

func (s *Service) UpsertRolePermissionAudited(actorID int, rp *RolePermission) error {
	// Capture previous value if exists, for audit diff.
	var old *int
	existing, _ := s.repo.ListRolePermissionsByRole(rp.RoleName)
	for _, e := range existing {
		if e.PermissionTypeID == rp.PermissionTypeID {
			v := e.Value
			old = &v
			break
		}
	}
	if err := s.UpsertRolePermission(rp); err != nil {
		return err
	}
	pid := rp.PermissionTypeID
	newVal := rp.Value
	s.audit(actorID, AuditActionGrant, AuditTargetRole, rp.RoleName, &pid, old, &newVal, "")
	return nil
}

func (s *Service) DeleteRolePermissionAudited(actorID int, roleName string, permissionTypeID int) error {
	if err := s.DeleteRolePermission(roleName, permissionTypeID); err != nil {
		return err
	}
	pid := permissionTypeID
	s.audit(actorID, AuditActionRevoke, AuditTargetRole, roleName, &pid, nil, nil, "")
	return nil
}

func (s *Service) UpsertUserPermissionAudited(actorID int, up *UserPermission) error {
	var old *int
	existing, _ := s.repo.ListUserPermissions(up.UserID)
	for _, e := range existing {
		if e.PermissionTypeID == up.PermissionTypeID {
			v := e.Value
			old = &v
			break
		}
	}
	if err := s.UpsertUserPermission(up); err != nil {
		return err
	}
	pid := up.PermissionTypeID
	newVal := up.Value
	s.audit(actorID, AuditActionGrant, AuditTargetUser, strconv.Itoa(up.UserID), &pid, old, &newVal, "")
	return nil
}

func (s *Service) DeleteUserPermissionAudited(actorID int, userID, permissionTypeID int) error {
	if err := s.DeleteUserPermission(userID, permissionTypeID); err != nil {
		return err
	}
	pid := permissionTypeID
	s.audit(actorID, AuditActionRevoke, AuditTargetUser, strconv.Itoa(userID), &pid, nil, nil, "")
	return nil
}

func (s *Service) DeleteAllUserPermissionsAudited(actorID int, userID int) error {
	if err := s.DeleteAllUserPermissions(userID); err != nil {
		return err
	}
	s.audit(actorID, AuditActionResetUser, AuditTargetUser, strconv.Itoa(userID), nil, nil, nil, "")
	return nil
}
