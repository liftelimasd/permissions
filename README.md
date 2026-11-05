# permissions

Sistema de permisos centralizado, multi-aplicación, con roles, overrides por usuario y auditoría — pensado para un servicio `usersmanager` que dé soporte a múltiples aplicaciones (sat01, cloud, etc.).

> **Breaking changes vs. v1.** Esta versión introduce el concepto de `application`, cambia firmas de `Resolve`, sustituye `UserFinder` por `UserDirectory` y añade auditoría. Si tu servicio sigue en v1, no actualices a v2 hasta migrar.

## Instalación

```bash
go get github.com/liftelimasd/permissions/v2@latest
```

Usa `v2.0.1` o posterior: el tag `v2.0.0` apunta al commit de la v0.2.0 (módulo sin `/v2`) y Go no lo acepta.

```go
import (
    "github.com/liftelimasd/permissions/v2"
    permgorm "github.com/liftelimasd/permissions/v2/gorm"
    ginhttp  "github.com/liftelimasd/permissions/v2/ginhttp"
)
```

---

## Modelo

Cinco tablas:

| Tabla | Qué guarda |
|-------|-----------|
| `applications` | Catálogo de aplicaciones (`sat01`, `cloud`, ...) |
| `permission_types` | Catálogo de permisos por aplicación (`application_key + key + default_value`) |
| `roles` | Roles globales (no namespaced por app) |
| `role_permissions` | Valor de cada permiso para cada rol |
| `user_permissions` | Overrides personalizados por usuario |
| `permission_audit_log` | Registro de cada mutación (quién, qué, cuándo, antes/después) |

Rango de valores: **0–3** (0 = sin acceso, 3 = acceso total).

**Resolución** (`Resolve`):
1. Semilla con `default_value` de cada `permission_type` de la app.
2. Para cada rol del usuario → aplica `role_permissions`. Si un permiso aparece en varios roles, **gana el mayor**.
3. Aplica `user_permissions` **incondicionalmente** — el override de usuario siempre gana.

---

## Integración

### 1. Migrar el schema

```go
if err := permgorm.Migrate(db); err != nil {
    log.Fatalf("permissions migrate: %v", err)
}
```

### 2. Construir el servicio

```go
repo    := permgorm.NewRepository(db)
permSvc := permissions.NewService(repo)
```

### 3. Implementar `UserDirectory`

El paquete no tiene tabla `users` propia. El host (tu `usersmanager`) la expone vía adaptador:

```go
type UserDirectory interface {
    FindByUsername(username string) (User, error)
    FindByID(id int) (User, error)
    List(offset, limit int) ([]User, int, error)
    RolesOf(userID int) ([]string, error) // roles que el host asigna al usuario
}

type User struct {
    ID       int
    Username string
}
```

Ejemplo apuntando a una tabla con columnas distintas (`login` en vez de `username`):

```go
type myDirectory struct{ db *gorm.DB }

func (d *myDirectory) FindByUsername(username string) (ginhttp.User, error) {
    var u struct{ ID int; Login string }
    err := d.db.Table("users").Select("id, login").
        Where("login = ?", username).First(&u).Error
    return ginhttp.User{ID: u.ID, Username: u.Login}, err
}

func (d *myDirectory) FindByID(id int) (ginhttp.User, error) {
    var u struct{ ID int; Login string }
    err := d.db.Table("users").Select("id, login").
        Where("id = ?", id).First(&u).Error
    return ginhttp.User{ID: u.ID, Username: u.Login}, err
}

func (d *myDirectory) List(offset, limit int) ([]ginhttp.User, int, error) {
    var total int64
    d.db.Table("users").Count(&total)
    var rows []struct{ ID int; Login string }
    err := d.db.Table("users").Select("id, login").
        Offset(offset).Limit(limit).Find(&rows).Error
    out := make([]ginhttp.User, len(rows))
    for i, r := range rows {
        out[i] = ginhttp.User{ID: r.ID, Username: r.Login}
    }
    return out, int(total), err
}
```

`RolesOf` devuelve los roles que el host asigna al usuario (por ejemplo, de una tabla `user_roles`). Lo usa `GET /users/:username/resolved` para que la vista previa coincida con lo que el usuario recibe de verdad:

```go
func (d *myDirectory) RolesOf(userID int) ([]string, error) {
    var roles []string
    err := d.db.Table("user_roles").Where("user_id = ?", userID).Pluck("role", &roles).Error
    return roles, err
}
```

El paquete nunca toca `password`, `companyId` u otros campos. Quedan bajo el control del host.

### 4. Actor en el contexto (auditoría)

Cada endpoint mutante necesita saber **quién** está haciendo la acción. Tu middleware de auth tiene que dejar el ID en el contexto de Gin:

```go
protected.Use(func(c *gin.Context) {
    userID := extractFromJWT(c) // tu lógica
    c.Set("actorUserID", userID)
    c.Next()
})
```

Si el actor no está presente al llegar al handler, la respuesta es `401 unauthenticated`. Si prefieres otra clave o lógica, pásala al registrar rutas:

```go
ginhttp.RegisterRoutes(protected, permSvc, dir, func(c *gin.Context) (int, bool) {
    // tu lógica custom
})
```

Pasa `nil` para usar la lectura por defecto (`actorUserID` del contexto).

### 5. Registrar rutas

```go
protected := router.Group("/permissions")
protected.Use(tuAuthMiddleware())
ginhttp.RegisterRoutes(protected, permSvc, &myDirectory{db: db}, nil)
```

### 6. Devolver permisos en el login

**Patrón recomendado**: token JWT mínimo + permisos en el body, scopeados a la aplicación que hace login.

```go
app := ctx.Query("app") // "sat01", "cloud", "all", ...

if app == "all" && !isAdmin(user) {
    // restringir: app=all solo para admins
}

if app == "all" {
    perms, _ := permSvc.ResolveAll(userID, roleNames)
    response.Permissions = perms // map[appKey]map[permKey]int
} else {
    perms, _ := permSvc.Resolve(userID, roleNames, app)
    response.Permissions = perms // map[permKey]int (plano)
}
```

Respuesta para un login normal (`app=sat01`):

```json
{
  "token": "eyJ...",
  "permissions": { "crudSat": 3, "viewReports": 2 }
}
```

Respuesta para el panel admin (`app=all`):

```json
{
  "token": "eyJ...",
  "permissions": {
    "sat01":        { "crudSat": 3, "viewReports": 2 },
    "cloud":        { "crudCloud": 2 },
    "usersmanager": { "manageUsers": 1 }
  }
}
```

---

## Endpoints

Todos bajo el prefijo de `RegisterRoutes` (en los ejemplos, `/permissions`).

### Aplicaciones

| Método | Ruta | Body | Acción |
|--------|------|------|--------|
| `GET` | `/applications` | — | Listar |
| `POST` | `/applications` | `{"key":"sat01","name":"SAT","description":"..."}` | Crear |
| `PUT` | `/applications/:app` | `{"name":"...","description":"..."}` | Editar |
| `DELETE` | `/applications/:app` | — | Borrar (cascada a sus `permission_types`) |

`key` debe cumplir `^[a-zA-Z0-9_-]+$`.

### Tipos de permiso

| Método | Ruta | Body | Acción |
|--------|------|------|--------|
| `GET` | `/types` | — | Listar todos (todas las apps) |
| `GET` | `/applications/:app/types` | — | Listar de una app |
| `POST` | `/applications/:app/types` | `{"key":"crudSat","description":"...","defaultValue":0}` | Crear |
| `PUT` | `/types/:id` | `{"description":"...","defaultValue":1}` | Editar |
| `DELETE` | `/types/:id` | — | Borrar (cascada a role/user perms) |

Unicidad: `(application_key, key)`. La misma `key` puede existir en apps diferentes.

`key` debe cumplir `^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`: admite puntos para agrupar permisos relacionados (`screens`, `screens.config`).

### Roles

| Método | Ruta | Body | Acción |
|--------|------|------|--------|
| `GET` | `/roles` | — | Listar |
| `POST` | `/roles` | `{"name":"admin","description":"..."}` | Crear |
| `PUT` | `/roles/:name` | `{"description":"..."}` | Editar |
| `DELETE` | `/roles/:name` | — | Borrar (cascada) |
| `GET` | `/roles/:name/permissions` | — | Ver permisos |
| `PUT` | `/roles/:name/permissions` | ver abajo | Upsert masivo |
| `DELETE` | `/roles/:name/permissions/:app/:key` | — | Quitar uno |

Body del upsert (namespaced por app):

```json
{
  "permissions": {
    "sat01": { "crudSat": 3, "viewReports": 2 },
    "cloud": { "crudCloud": 1 }
  }
}
```

El cuerpo se valida entero antes de escribir nada:

- Una aplicación o llave que no existe responde `400` con la lista en `unknown` (`["cloud:crudClod"]`).
- Un valor fuera de 0–3 responde `400` con la lista en `invalid`.

Si todo es válido, los cambios y su auditoría se aplican en una sola transacción cuando el repositorio implementa `TxRepository` (`permgorm` lo hace): o se aplican todos o ninguno.

`DELETE /roles/:name` responde `409` si el host lo impide con `ErrRoleInUse` (por ejemplo, porque el rol sigue asignado a usuarios).

### Permisos de usuario

| Método | Ruta | Body | Acción |
|--------|------|------|--------|
| `GET` | `/users/:username` | — | Ver overrides |
| `PUT` | `/users/:username` | igual shape que en roles | Upsert masivo |
| `DELETE` | `/users/:username/:app/:key` | — | Quitar override |
| `POST` | `/users/:username/reset` | — | Borrar todos los overrides |
| `GET` | `/users/:username/resolved` | — | Mapa resuelto |
| `GET` | `/users/:username/resolved?app=sat01` | — | Mapa resuelto **plano** para esa app |
| `GET` | `/users/:username/resolved?app=all` | — | Mapa **anidado** para todas |

`/resolved` usa los roles que devuelve `UserDirectory.RolesOf`.

### Directorio de usuarios

| Método | Ruta | Acción |
|--------|------|--------|
| `GET` | `/users?offset=0&limit=50` | Paginado, devuelve `{users, total, offset, limit}` |

### Auditoría

| Método | Ruta | Acción |
|--------|------|--------|
| `GET` | `/audit?offset=0&limit=50` | Listar entradas (más recientes primero) |

Cada entrada contiene: `actorUserId`, `action` (`grant`/`revoke`/`create`/`update`/`delete`/`reset_user`), `targetType` (`application`/`role`/`permission_type`/`user`), `targetId`, `permissionTypeId`, `oldValue`, `newValue`, `createdAt`.

---

## API del Service (sin Gin)

Si no usas Gin, llama directamente al `Service`. Tienes dos variantes por mutación:

- **Sin auditoría** (`CreateRole`, `UpsertUserPermission`, ...): útil para seeds / migraciones / tests.
- **Con auditoría** (`CreateRoleAudited(actorID, ...)`, `UpsertUserPermissionAudited(actorID, ...)`): para flujos donde sí hay un actor identificado.

```go
// Login per-app
perms, err := permSvc.Resolve(userID, []string{"admin"}, "sat01")

// Panel admin (todas las apps)
all, err := permSvc.ResolveAll(userID, []string{"admin"})

// Batch para listados
batch, err := permSvc.ResolveBatch([]permissions.UserRoles{
    {UserID: 1, Roles: []string{"admin"}},
    {UserID: 2, Roles: []string{"viewer"}},
}, "sat01")

// Mutación auditada
err := permSvc.UpsertUserPermissionAudited(actorID, &permissions.UserPermission{
    UserID: 42, PermissionTypeID: 7, Value: 3,
})
```

---

## Errores tipados

```go
permissions.ErrApplicationNotFound
permissions.ErrApplicationExists
permissions.ErrInvalidApplicationKey
permissions.ErrRoleNotFound
permissions.ErrRoleExists
permissions.ErrInvalidRoleName
permissions.ErrTypeNotFound
permissions.ErrTypeKeyExists
permissions.ErrInvalidTypeKey
permissions.ErrInvalidValue
permissions.ErrUnknownPermissions
permissions.ErrRoleInUse // lo devuelve el host al borrar un rol en uso
```

El adaptador `ginhttp` ya los mapea a los códigos HTTP correctos (`404`, `409`, `400`).

Para agrupar varios cambios, `Service.Atomic(func(s *permissions.Service) error { ... })` los ejecuta en una transacción si el repositorio implementa `TxRepository`.

---

## Esquema SQL (si no usas AutoMigrate)

```sql
CREATE TABLE applications (
    `key`       VARCHAR(50)  NOT NULL,
    name        VARCHAR(100) NOT NULL,
    description VARCHAR(255),
    created_at  DATETIME,
    updated_at  DATETIME,
    PRIMARY KEY (`key`)
);

CREATE TABLE roles (
    name        VARCHAR(100) NOT NULL,
    description VARCHAR(255),
    created_at  DATETIME,
    updated_at  DATETIME,
    PRIMARY KEY (name)
);

CREATE TABLE permission_types (
    id              INT          NOT NULL AUTO_INCREMENT,
    application_key VARCHAR(50)  NOT NULL,
    `key`           VARCHAR(100) NOT NULL,
    description     VARCHAR(255),
    default_value   TINYINT      NOT NULL DEFAULT 0,
    created_at      DATETIME,
    updated_at      DATETIME,
    PRIMARY KEY (id),
    UNIQUE KEY uq_app_key (application_key, `key`),
    CONSTRAINT fk_pt_app FOREIGN KEY (application_key)
        REFERENCES applications(`key`) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE role_permissions (
    id                 INT          NOT NULL AUTO_INCREMENT,
    role_name          VARCHAR(100) NOT NULL,
    permission_type_id INT          NOT NULL,
    value              TINYINT      NOT NULL,
    created_at         DATETIME,
    updated_at         DATETIME,
    PRIMARY KEY (id),
    UNIQUE KEY uq_role_perm (role_name, permission_type_id),
    CONSTRAINT fk_rp_role FOREIGN KEY (role_name)
        REFERENCES roles(name) ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT fk_rp_type FOREIGN KEY (permission_type_id)
        REFERENCES permission_types(id) ON DELETE CASCADE
);

CREATE TABLE user_permissions (
    id                 INT     NOT NULL AUTO_INCREMENT,
    user_id            INT     NOT NULL,
    permission_type_id INT     NOT NULL,
    value              TINYINT NOT NULL,
    created_at         DATETIME,
    updated_at         DATETIME,
    PRIMARY KEY (id),
    UNIQUE KEY uq_user_perm (user_id, permission_type_id),
    CONSTRAINT fk_up_type FOREIGN KEY (permission_type_id)
        REFERENCES permission_types(id) ON DELETE CASCADE
);

CREATE TABLE permission_audit_log (
    id                 INT          NOT NULL AUTO_INCREMENT,
    actor_user_id      INT          NOT NULL,
    action             VARCHAR(32)  NOT NULL,
    target_type        VARCHAR(32)  NOT NULL,
    target_id          VARCHAR(100) NOT NULL,
    permission_type_id INT,
    old_value          INT,
    new_value          INT,
    metadata           TEXT,
    created_at         DATETIME,
    PRIMARY KEY (id),
    KEY idx_audit_actor (actor_user_id),
    KEY idx_audit_target (target_type, target_id),
    KEY idx_audit_created (created_at)
);
```

---

## Notas de seguridad

- **`app=all` debe estar restringido a admins**. La librería no aplica esa restricción — la decides en tu handler de login o con un middleware.
- **Token mínimo**: no metas todos los permisos en el JWT. El patrón aquí es token con `userID + roles + exp`, permisos en el body del login y/o consultados vía `/resolved` con cache local en el cliente.
- **Auditoría no bloquea**: si la inserción del log falla, la operación principal continúa. El log es best-effort para no romper la BD ante un fallo de auditoría.
