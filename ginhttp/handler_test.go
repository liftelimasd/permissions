package ginhttp_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	permissions "github.com/liftelimasd/permissions/v2"
	"github.com/liftelimasd/permissions/v2/ginhttp"
	permgorm "github.com/liftelimasd/permissions/v2/gorm"
)

// directory is a fake host user directory with a single user, vicente (ID 7).
type directory struct{ roles map[int][]string }

func (d directory) FindByUsername(username string) (ginhttp.User, error) {
	if username != "vicente" {
		return ginhttp.User{}, errors.New("not found")
	}
	return ginhttp.User{ID: 7, Username: username}, nil
}

func (d directory) FindByID(id int) (ginhttp.User, error) {
	if id != 7 {
		return ginhttp.User{}, errors.New("not found")
	}
	return ginhttp.User{ID: 7, Username: "vicente"}, nil
}

func (d directory) List(offset, limit int) ([]ginhttp.User, int, error) {
	return []ginhttp.User{{ID: 7, Username: "vicente"}}, 1, nil
}

func (d directory) RolesOf(userID int) ([]string, error) { return d.roles[userID], nil }

// newRouter mounts the permission routes over a fresh in-memory database with
// application "one" (screens, users), the role "tecnico" (screens = 2) and
// vicente holding that role. withActor sets the actor the audit log needs.
func newRouter(t *testing.T, withActor bool) (*gin.Engine, *permissions.Service) {
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
	must(t, svc.CreateApplication(&permissions.Application{Key: "one", Name: "liftel_one"}))
	must(t, svc.CreateType(&permissions.PermissionType{ApplicationKey: "one", Key: "screens"}))
	must(t, svc.CreateType(&permissions.PermissionType{ApplicationKey: "one", Key: "users"}))
	must(t, svc.CreateRole(&permissions.Role{Name: "tecnico"}))
	screens, err := svc.GetTypeByKey("one", "screens")
	must(t, err)
	must(t, svc.UpsertRolePermission(&permissions.RolePermission{RoleName: "tecnico", PermissionTypeID: screens.ID, Value: 2}))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/permissions")
	if withActor {
		g.Use(func(c *gin.Context) { c.Set("actorUserID", 1); c.Next() })
	}
	ginhttp.RegisterRoutes(g, svc, directory{roles: map[int][]string{7: {"tecnico"}}}, nil)
	return r, svc
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func do(r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, &buf))
	return w
}

func TestResolvedUsesTheUserRoles(t *testing.T) {
	r, _ := newRouter(t, true)
	w := do(r, http.MethodGet, "/permissions/users/vicente/resolved?app=one", nil)
	var got map[string]int
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != http.StatusOK || got["screens"] != 2 || got["users"] != 0 {
		t.Errorf("GET resolved = %d %s, want screens=2 from the tecnico role", w.Code, w.Body.String())
	}
}

func TestUpsertRejectsUnknownKeysWithoutWriting(t *testing.T) {
	r, svc := newRouter(t, true)
	body := map[string]any{"permissions": map[string]map[string]int{
		"one":  {"screns": 3, "users": 1},
		"nope": {"x": 1},
	}}
	w := do(r, http.MethodPut, "/permissions/roles/tecnico/permissions", body)
	var resp struct {
		Unknown []string `json:"unknown"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != http.StatusBadRequest || !reflect.DeepEqual(resp.Unknown, []string{"nope:x", "one:screns"}) {
		t.Errorf("PUT = %d %s, want 400 listing nope:x and one:screns", w.Code, w.Body.String())
	}
	perms, err := svc.ListRolePermissionsByRole("tecnico")
	must(t, err)
	if len(perms) != 1 { // only the screens = 2 set up by newRouter
		t.Errorf("role permissions after a rejected PUT = %v, want them unchanged", perms)
	}
}

func TestUpsertRejectsOutOfRangeValues(t *testing.T) {
	r, svc := newRouter(t, true)
	body := map[string]any{"permissions": map[string]map[string]int{"one": {"users": 5, "screens": 1}}}
	w := do(r, http.MethodPut, "/permissions/users/vicente", body)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "one:users") {
		t.Errorf("PUT = %d %s, want 400 naming one:users", w.Code, w.Body.String())
	}
	perms, err := svc.ListUserPermissions(7)
	must(t, err)
	if len(perms) != 0 {
		t.Errorf("user permissions after a rejected PUT = %v, want none", perms)
	}
}

func TestUpsertUserPermissionsTwiceKeepsOneRow(t *testing.T) {
	r, _ := newRouter(t, true)
	for _, v := range []int{1, 3} {
		body := map[string]any{"permissions": map[string]map[string]int{"one": {"users": v}}}
		if w := do(r, http.MethodPut, "/permissions/users/vicente", body); w.Code != http.StatusOK {
			t.Fatalf("PUT users=%d = %d %s", v, w.Code, w.Body.String())
		}
	}
	w := do(r, http.MethodGet, "/permissions/users/vicente", nil)
	var perms []permissions.UserPermission
	_ = json.Unmarshal(w.Body.Bytes(), &perms)
	if len(perms) != 1 || perms[0].Value != 3 {
		t.Errorf("GET user permissions = %s, want one row with value 3", w.Body.String())
	}
}

func TestMutationsNeedAnActor(t *testing.T) {
	r, _ := newRouter(t, false)
	body := map[string]any{"permissions": map[string]map[string]int{"one": {"users": 1}}}
	if w := do(r, http.MethodPut, "/permissions/users/vicente", body); w.Code != http.StatusUnauthorized {
		t.Errorf("PUT without actor = %d, want 401", w.Code)
	}
}
