package permissions_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	permissions "github.com/liftelimasd/permissions/v2"
	permgorm "github.com/liftelimasd/permissions/v2/gorm"
)

// newService returns a Service over a fresh in-memory SQLite database with two
// applications ("one" with screens and users, "sat" with screens defaulting to
// 1) and the roles "tecnico" and "supervisor".
func newService(t *testing.T) (*permissions.Service, *gorm.DB) {
	t.Helper()
	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := permgorm.Migrate(db); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	svc := permissions.NewService(permgorm.NewRepository(db))
	mustOK(t, svc.CreateApplication(&permissions.Application{Key: "one", Name: "liftel_one"}))
	mustOK(t, svc.CreateApplication(&permissions.Application{Key: "sat", Name: "sat01"}))
	mustOK(t, svc.CreateType(&permissions.PermissionType{ApplicationKey: "one", Key: "screens"}))
	mustOK(t, svc.CreateType(&permissions.PermissionType{ApplicationKey: "one", Key: "users"}))
	mustOK(t, svc.CreateType(&permissions.PermissionType{ApplicationKey: "sat", Key: "screens", DefaultValue: 1}))
	mustOK(t, svc.CreateRole(&permissions.Role{Name: "tecnico"}))
	mustOK(t, svc.CreateRole(&permissions.Role{Name: "supervisor"}))
	return svc, db
}

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func typeID(t *testing.T, svc *permissions.Service, app, key string) int {
	t.Helper()
	pt, err := svc.GetTypeByKey(app, key)
	if err != nil {
		t.Fatalf("type %s:%s: %v", app, key, err)
	}
	return pt.ID
}

func TestResolvePerApplication(t *testing.T) {
	svc, _ := newService(t)
	oneScreens, oneUsers := typeID(t, svc, "one", "screens"), typeID(t, svc, "one", "users")
	mustOK(t, svc.UpsertRolePermission(&permissions.RolePermission{RoleName: "tecnico", PermissionTypeID: oneScreens, Value: 2}))
	mustOK(t, svc.UpsertRolePermission(&permissions.RolePermission{RoleName: "supervisor", PermissionTypeID: oneScreens, Value: 1}))
	mustOK(t, svc.UpsertRolePermission(&permissions.RolePermission{RoleName: "supervisor", PermissionTypeID: oneUsers, Value: 3}))
	// The user override wins even when it is lower than the role value.
	mustOK(t, svc.UpsertUserPermission(&permissions.UserPermission{UserID: 7, PermissionTypeID: oneUsers, Value: 0}))

	got, err := svc.Resolve(7, []string{"tecnico", "supervisor"}, "one")
	mustOK(t, err)
	if got["screens"] != 2 || got["users"] != 0 || len(got) != 2 {
		t.Errorf("one = %v, want screens=2 (highest role) and users=0 (override)", got)
	}

	sat, err := svc.Resolve(7, []string{"tecnico", "supervisor"}, "sat")
	mustOK(t, err)
	if sat["screens"] != 1 || len(sat) != 1 {
		t.Errorf("sat = %v, want only the sat default screens=1", sat)
	}

	if _, err := svc.Resolve(7, nil, "missing"); !errors.Is(err, permissions.ErrApplicationNotFound) {
		t.Errorf("unknown application: err = %v, want ErrApplicationNotFound", err)
	}
}

func TestUserPermissionUpsertUpdatesInPlace(t *testing.T) {
	svc, db := newService(t)
	id := typeID(t, svc, "one", "users")
	mustOK(t, svc.UpsertUserPermission(&permissions.UserPermission{UserID: 7, PermissionTypeID: id, Value: 1}))
	mustOK(t, svc.UpsertUserPermission(&permissions.UserPermission{UserID: 7, PermissionTypeID: id, Value: 3}))

	var rows int64
	mustOK(t, db.Table("user_permissions").Where("user_id = ?", 7).Count(&rows).Error)
	perms, err := svc.ListUserPermissions(7)
	mustOK(t, err)
	if rows != 1 || len(perms) != 1 || perms[0].Value != 3 {
		t.Errorf("rows=%d perms=%v, want a single row with value 3", rows, perms)
	}
}

func TestRolePermissionUpsertUpdatesInPlace(t *testing.T) {
	svc, db := newService(t)
	id := typeID(t, svc, "one", "screens")
	mustOK(t, svc.UpsertRolePermission(&permissions.RolePermission{RoleName: "tecnico", PermissionTypeID: id, Value: 1}))
	mustOK(t, svc.UpsertRolePermission(&permissions.RolePermission{RoleName: "tecnico", PermissionTypeID: id, Value: 2}))

	var rows int64
	mustOK(t, db.Table("role_permissions").Where("role_name = ?", "tecnico").Count(&rows).Error)
	perms, err := svc.ListRolePermissionsByRole("tecnico")
	mustOK(t, err)
	if rows != 1 || len(perms) != 1 || perms[0].Value != 2 {
		t.Errorf("rows=%d perms=%v, want a single row with value 2", rows, perms)
	}
}

func TestCreateTypeValidatesKey(t *testing.T) {
	svc, _ := newService(t)
	for key, valid := range map[string]bool{
		"screens.config":     true,
		"auto_notifications": true,
		"calls-audio":        true,
		"con espacio":        false,
		".screens":           false,
		"ñandú":              false,
		"":                   false,
	} {
		err := svc.CreateType(&permissions.PermissionType{ApplicationKey: "one", Key: key})
		if valid && err != nil {
			t.Errorf("CreateType(%q) = %v, want ok", key, err)
		}
		if !valid && !errors.Is(err, permissions.ErrInvalidTypeKey) {
			t.Errorf("CreateType(%q) = %v, want ErrInvalidTypeKey", key, err)
		}
	}
}

func TestAtomicRollsBackOnError(t *testing.T) {
	svc, _ := newService(t)
	id := typeID(t, svc, "one", "screens")
	boom := errors.New("boom")
	err := svc.Atomic(func(s *permissions.Service) error {
		if err := s.UpsertRolePermissionAudited(1, &permissions.RolePermission{RoleName: "tecnico", PermissionTypeID: id, Value: 3}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Atomic = %v, want boom", err)
	}
	perms, err := svc.ListRolePermissionsByRole("tecnico")
	mustOK(t, err)
	_, total, err := svc.ListAuditLogs(0, 10)
	mustOK(t, err)
	if len(perms) != 0 || total != 0 {
		t.Errorf("after rollback: role perms=%v audit rows=%d, want none", perms, total)
	}
}

func TestAuditRecordsOldAndNewValues(t *testing.T) {
	svc, _ := newService(t)
	id := typeID(t, svc, "one", "users")
	mustOK(t, svc.UpsertRolePermissionAudited(42, &permissions.RolePermission{RoleName: "tecnico", PermissionTypeID: id, Value: 1}))
	mustOK(t, svc.UpsertRolePermissionAudited(42, &permissions.RolePermission{RoleName: "tecnico", PermissionTypeID: id, Value: 3}))
	mustOK(t, svc.DeleteTypeAudited(42, id))

	logs, total, err := svc.ListAuditLogs(0, 10)
	mustOK(t, err)
	if total != 3 {
		t.Fatalf("audit rows = %d, want 3", total)
	}
	del, upd := logs[0], logs[1] // newest first
	if del.Action != permissions.AuditActionDelete || del.TargetID != "one:users" {
		t.Errorf("delete entry = %+v, want target one:users", del)
	}
	if upd.ActorUserID != 42 || upd.OldValue == nil || *upd.OldValue != 1 || upd.NewValue == nil || *upd.NewValue != 3 {
		t.Errorf("update entry = %+v, want actor 42, old 1, new 3", upd)
	}
}
