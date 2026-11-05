package ginhttp

type CreateRoleRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

type UpdateRoleRequest struct {
	Description string `json:"description"`
}

type CreateApplicationRequest struct {
	Key         string `json:"key" binding:"required"`
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

type UpdateApplicationRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type CreateTypeRequest struct {
	Key          string `json:"key" binding:"required"`
	Description  string `json:"description"`
	DefaultValue int    `json:"defaultValue"`
}

type UpdateTypeRequest struct {
	Description  string `json:"description"`
	DefaultValue int    `json:"defaultValue"`
}

// UpsertPermissionsRequest is the user-permission upsert body.
// Shape: { "permissions": { "<appKey>": { "<permKey>": <value> } } }
type UpsertPermissionsRequest struct {
	Permissions map[string]map[string]int `json:"permissions" binding:"required"`
}

// UpsertRolePermissionsRequest is the role-permission upsert body.
// Shape: { "permissions": { "<appKey>": { "<permKey>": <value> } } }
type UpsertRolePermissionsRequest struct {
	Permissions map[string]map[string]int `json:"permissions" binding:"required"`
}
