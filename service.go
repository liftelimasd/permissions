package permissions

import "regexp"

var roleNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type Service struct {
	repo Repository
}

func NewService(repo Repository) *Service {
	return &Service{repo: repo}
}

// Resolve builds the final permissions map for a user given their role names.
//
// Resolution order:
//  1. Seed with default_value of every permission_type.
//  2. For each role the user has, apply its role_permissions — highest value wins
//     when a permission appears in multiple roles.
//  3. Apply user_permissions unconditionally — user overrides always win,
//     even if the value is lower than the role-level value.
func (s *Service) Resolve(userID int, roleNames []string) (map[string]int, error) {
	types, err := s.repo.ListTypes()
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

// UserRoles is the input pair for ResolveBatch.
type UserRoles struct {
	UserID int
	Roles  []string
}

// ResolveBatch resolves permissions for many users in 3 queries total,
// independent of the number of users. Returns a map keyed by UserID.
//
// Resolution semantics are identical to Resolve:
//  1. Seed with default_value of every permission_type.
//  2. Apply role_permissions of all the user's roles — highest value wins.
//  3. Apply user_permissions — overrides always win.
//
// Users whose roles aren't registered or who have no overrides still get
// a map populated with the catalog defaults.
func (s *Service) ResolveBatch(users []UserRoles) (map[int]map[string]int, error) {
	result := make(map[int]map[string]int, len(users))
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

// --- Roles ---

func (s *Service) ListRoles() ([]Role, error) { return s.repo.ListRoles() }
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

// --- Permission types ---

func (s *Service) ListTypes() ([]PermissionType, error) { return s.repo.ListTypes() }

func (s *Service) GetType(id int) (*PermissionType, error) {
	pt, err := s.repo.GetType(id)
	if err != nil {
		return nil, ErrTypeNotFound
	}
	return pt, nil
}

func (s *Service) CreateType(pt *PermissionType) error {
	if err := validateValue(pt.DefaultValue); err != nil {
		return err
	}
	if _, err := s.repo.GetTypeByKey(pt.Key); err == nil {
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
