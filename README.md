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

El paquete HTTP traduce `username → userID` en cada request a `/users/:username`. Para eso necesita que implementes la interfaz `ginhttp.UserFinder`:

```go
type UserFinder interface {
    FindUserID(username string) (int, error)
}
```

**Esta interfaz la escribes tú** en tu servicio. La librería no sabe nada de tu modelo de usuarios: solo llama a `FindUserID` y espera un `int`. Si el usuario no existe, devuelve un error y el endpoint responde `404 user not found`.

#### Requisito: tabla `users` en tu servicio

Para que el `UserFinder` funcione, **tu servicio necesita una tabla de usuarios** con al menos `id` (INT) y `username` (VARCHAR). Ejemplo mínimo:

```sql
CREATE TABLE users (
    id       INT          NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uq_username (username)
);
```

La implementación típica del `UserFinder` apunta a esa tabla:

```go
import ginhttp "github.com/liftelimasd/permissions/ginhttp"

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

#### Alternativas si no tienes tabla propia de usuarios

- **Auth service externo** (Keycloak, Auth0, etc.): implementa `FindUserID` haciendo una llamada HTTP al servicio de identidad para obtener el ID numérico del usuario.
- **Sin IDs numéricos**: si tu sistema identifica usuarios solo por string (email, sub de JWT), puedes mantener una tabla mínima `{id, username}` solo para este mapeo, o adaptar el `UserFinder` para generar/recuperar un ID a partir del username de forma determinista.

> El campo `user_id` en `user_permissions` no tiene FK hacia ninguna tabla de usuarios — la librería lo deja intencionalmente como entero opaco. Si quieres añadir la FK en tu migración, puedes hacerlo sin tocar este paquete.

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

## Resolución por lotes (`ResolveBatch`)

Para endpoints que devuelven listas de usuarios y necesitan incluir los permisos de cada uno, usa `ResolveBatch`. Hace **3 queries totales** independientemente del número de usuarios (vs `N × 3` queries de llamar a `Resolve` en bucle).

```go
input := []permissions.UserRoles{
    {UserID: 12, Roles: []string{"admin"}},
    {UserID: 13, Roles: []string{"editor"}},
    {UserID: 14, Roles: []string{"viewer", "editor"}},
}

permsByUser, err := permSvc.ResolveBatch(input)
// permsByUser[12] → map[string]int{ "screensAcceso": 3, ... }
// permsByUser[13] → map[string]int{ "screensAcceso": 1, ... }
```

Mismas reglas de resolución que `Resolve` (defaults → roles con máximo → overrides incondicionales).

---

## Usernames vs IDs

La librería trabaja con dos identificadores distintos según la capa:

| Capa | Identificador | Ejemplo |
|------|--------------|---------|
| API HTTP (URL) | `username` string | `/users/vicenteT` |
| Base de datos | `user_id` int | `user_id: 42` |

En cada request a `/users/:username`, el handler llama a `UserFinder.FindUserID` para obtener el ID numérico antes de tocar la base de datos. **El username nunca se persiste** — solo existe en la URL.

### Flujo de autorización (responsabilidad del servicio anfitrión)

La librería no valida que el username de la URL coincida con el del token JWT. Eso es responsabilidad tuya. Las opciones habituales:

- **Middleware de auth**: antes de que llegue al handler de permisos, tu middleware comprueba que el usuario del token tiene permiso para gestionar permisos de ese username (p.ej. es admin, o es el propio usuario).
- **Endpoint `/me`**: expones `/permissions/me/resolved` en tu servicio que extrae el username del token directamente, sin aceptarlo como parámetro de URL.

```go
// Ejemplo: middleware que restringe /users/:username al propio usuario o a admins
protected.Use(func(c *gin.Context) {
    tokenUser := c.GetString("username") // set by your auth middleware
    paramUser := c.Param("username")
    if tokenUser != paramUser && !isAdmin(c) {
        c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
        return
    }
    c.Next()
})
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

> Si el username no existe en tu tabla de usuarios, todos estos endpoints devuelven `404 user not found`. La librería **no crea usuarios**.

#### Ejemplo: asignar un permiso único a un usuario concreto

Para dar acceso a `bestagent` solo a `vicenteT`, sin usar roles:

**Paso 1** — Crear el tipo de permiso (una sola vez):
```http
POST /permissions/types
{"key": "bestagent", "description": "Acceso a best agent", "defaultValue": 0}
```

**Paso 2** — Asignar el override al usuario:
```http
PUT /permissions/users/vicenteT
{"permissions": {"bestagent": 1}}
```

**Verificar**:
```http
GET /permissions/users/vicenteT/resolved
→ {"bestagent": 1, ...}
```

El resto de usuarios seguirán teniendo `bestagent: 0` (el `defaultValue`) a menos que también tengan un override o un rol con ese permiso.

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
