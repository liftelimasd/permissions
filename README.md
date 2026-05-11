# permissions

Sistema de permisos dinámicos por rol y por usuario para servicios Go.

## Instalación

```bash
go get github.com/liftelimasd/permissions@latest
```

Importa solo los subpaquetes que necesites:

```go
import (
    "github.com/liftelimasd/permissions"           // núcleo (siempre)
    permgorm   "github.com/liftelimasd/permissions/gorm"     // si usas GORM
    ginhttp    "github.com/liftelimasd/permissions/ginhttp"  // si usas Gin
)
```

---

## Cómo funciona

Tres tablas cooperan para producir un `map[string]int` de permisos en cada login:

| Tabla | Qué guarda |
|-------|-----------|
| `permission_types` | Catálogo de permisos disponibles (`key` + `default_value`) |
| `role_permissions` | Valor de cada permiso para cada rol |
| `user_permissions` | Overrides personalizados por usuario |

Rango de valores: **0–3** (0 = sin acceso, 3 = acceso total).

**Algoritmo de resolución** (`Resolve`):
1. Semilla con `default_value` de cada `permission_type`.
2. Para cada rol del usuario → aplica `role_permissions`. Si un permiso aparece en varios roles, **gana el mayor valor**.
3. Aplica `user_permissions` **incondicionalmente** — el override de usuario siempre gana, sea mayor o menor que el de rol.

---

## Integración en 5 pasos

### 1. Conectar y migrar

```go
import (
    permgorm "github.com/liftelimasd/permissions/gorm"
)

// db es tu *gorm.DB ya inicializado
if err := permgorm.Migrate(db); err != nil {
    log.Fatalf("permissions migrate: %v", err)
}
```

Esto crea las cuatro tablas si no existen. Llámalo al arrancar el servicio, tras conectar la BD.

### 2. Construir el repositorio y el servicio

```go
import (
    "github.com/liftelimasd/permissions"
    permgorm "github.com/liftelimasd/permissions/gorm"
)

repo    := permgorm.NewRepository(db)
permSvc := permissions.NewService(repo)
```

### 3. Implementar `UserFinder`

El paquete HTTP necesita resolver `username → userID` pero no conoce tu tabla de usuarios. Implementa una función:

```go
import ginhttp "github.com/liftelimasd/permissions/ginhttp"

// Implementa la interfaz ginhttp.UserFinder
type myUserFinder struct{ db *gorm.DB }

func (f *myUserFinder) FindUserID(username string) (int, error) {
    var u struct{ ID int }
    err := f.db.Table("users").
        Select("id").
        Where("username = ?", username).
        First(&u).Error
    return u.ID, err
}
```

### 4. Registrar las rutas HTTP

```go
import ginhttp "github.com/liftelimasd/permissions/ginhttp"

// Pasa un RouterGroup que ya tenga tu middleware de autenticación aplicado
protected := router.Group("/permissions")
protected.Use(tuAuthMiddleware())

ginhttp.RegisterRoutes(protected, permSvc, &myUserFinder{db: db})
```

Listo. Los endpoints quedan disponibles bajo `/permissions/...`.

### 5. Añadir permisos a la respuesta de login

```go
// roleNames viene de tu authservice (token, webhook, etc.)
roleNames := []string{"admin", "editor"}

// best-effort: si falla, el login sigue funcionando sin el campo
if perms, err := permSvc.Resolve(userID, roleNames); err == nil && len(perms) > 0 {
    response.Permissions = perms
}
```

Respuesta resultante:

```json
{
  "login": "usuario@empresa.com",
  "companyId": 1,
  "isPrimary": false,
  "permissions": {
    "screensAcceso": 1,
    "screensLista": 3,
    "reportesAcceso": 2
  }
}
```

---

## Endpoints

Todos quedan bajo el prefijo que uses en `RegisterRoutes` (en los ejemplos, `/permissions`).

### Tipos de permiso

| Método | Ruta | Body | Acción |
|--------|------|------|--------|
| `GET` | `/types` | — | Listar catálogo |
| `POST` | `/types` | `{"key":"screensAcceso","description":"...","defaultValue":0}` | Crear tipo |
| `PUT` | `/types/:id` | `{"description":"...","defaultValue":1}` | Editar |
| `DELETE` | `/types/:id` | — | Borrar (cascada a role/user perms) |

`key` debe cumplir `^[a-zA-Z0-9_-]+$`. `defaultValue` entre 0 y 3.

### Roles

| Método | Ruta | Body | Acción |
|--------|------|------|--------|
| `GET` | `/roles` | — | Listar roles registrados |
| `POST` | `/roles` | `{"name":"admin","description":"..."}` | Registrar rol |
| `PUT` | `/roles/:name` | `{"description":"..."}` | Editar descripción |
| `DELETE` | `/roles/:name` | — | Borrar rol + sus permisos (cascada) |
| `GET` | `/roles/:name/permissions` | — | Ver permisos del rol |
| `PUT` | `/roles/:name/permissions` | `{"permissions":{"screensAcceso":3}}` | Upsert masivo |
| `DELETE` | `/roles/:name/permissions/:key` | — | Quitar un permiso del rol |

> Los roles vienen de tu authservice externo. Regístralos aquí manualmente antes de asignarles permisos. Los roles del token que no existan en esta tabla se ignoran en `Resolve`.

### Permisos de usuario

| Método | Ruta | Body | Acción |
|--------|------|------|--------|
| `GET` | `/users/:username` | — | Ver overrides del usuario |
| `PUT` | `/users/:username` | `{"permissions":{"screensAcceso":2}}` | Upsert masivo de overrides |
| `DELETE` | `/users/:username/:key` | — | Quitar un override |
| `POST` | `/users/:username/reset` | — | Borrar todos los overrides (vuelve a los de rol) |
| `GET` | `/users/:username/resolved` | — | Preview del mapa resuelto (útil para debug/admin) |

---

## Esquema SQL (si prefieres no usar AutoMigrate)

```sql
CREATE TABLE roles (
    name        VARCHAR(100) NOT NULL,
    description VARCHAR(255),
    created_at  DATETIME,
    updated_at  DATETIME,
    PRIMARY KEY (name)
);

CREATE TABLE permission_types (
    id            INT          NOT NULL AUTO_INCREMENT,
    `key`         VARCHAR(100) NOT NULL,
    description   VARCHAR(255),
    default_value TINYINT      NOT NULL DEFAULT 0,
    created_at    DATETIME,
    updated_at    DATETIME,
    PRIMARY KEY (id),
    UNIQUE KEY uq_key (`key`)
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

-- user_id es opaco: este paquete no conoce tu tabla de usuarios.
-- Añade la FK a users(id) en tu propia migración si la necesitas.
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
```

> PostgreSQL: cambia `TINYINT` por `SMALLINT` y `AUTO_INCREMENT` por `SERIAL`.

---

## Errores tipados

```go
import "errors"
import "github.com/liftelimasd/permissions"

if errors.Is(err, permissions.ErrRoleNotFound)  { /* 404 */ }
if errors.Is(err, permissions.ErrRoleExists)    { /* 409 */ }
if errors.Is(err, permissions.ErrTypeNotFound)  { /* 404 */ }
if errors.Is(err, permissions.ErrTypeKeyExists) { /* 409 */ }
if errors.Is(err, permissions.ErrInvalidValue)  { /* 400 */ }
if errors.Is(err, permissions.ErrInvalidRoleName) { /* 400 */ }
```

El adaptador `ginhttp` ya mapea estos errores a los códigos HTTP correctos.

---

## Usar sin Gin (adaptador HTTP propio)

Si tu servicio usa `echo`, `chi`, o `net/http` directamente, no importes `ginhttp`. Usa el `Service` directamente y escribe tus propios handlers:

```go
import "github.com/liftelimasd/permissions"

// construir igual
repo    := miRepo{}           // implementa permissions.Repository
permSvc := permissions.NewService(repo)

// en tu handler de login
perms, err := permSvc.Resolve(userID, roleNames)

// en tu handler de CRUD
if err := permSvc.CreateType(&permissions.PermissionType{Key: "screensAcceso", DefaultValue: 0}); err != nil {
    // mapea el error a tu formato de respuesta
}
```

## Usar sin GORM (repositorio propio)

Implementa la interfaz `permissions.Repository` con tu cliente preferido (sqlx, pgx, mongo, etc.):

```go
type myRepo struct{ /* tu cliente */ }

func (r *myRepo) ListRoles() ([]permissions.Role, error)            { ... }
func (r *myRepo) GetRole(name string) (*permissions.Role, error)    { ... }
// ... resto de métodos de la interfaz

permSvc := permissions.NewService(&myRepo{})
```

---

## Estructura del repositorio

```
github.com/liftelimasd/permissions/
  entity.go       — tipos de dominio + constantes + errores
  repository.go   — interfaz Repository (puerto)
  service.go      — Service: Resolve + CRUD con validaciones
  gorm/
    models.go     — modelos GORM de las 4 tablas
    repository.go — NewRepository(db *gorm.DB) Repository
    migrate.go    — Migrate(db *gorm.DB) error
  ginhttp/
    dto.go        — structs de request JSON
    handler.go    — handlers Gin + interfaz UserFinder
    routes.go     — RegisterRoutes(group, svc, uf)
```
