package ginhttp

type CreateRoleRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

type UpdateRoleRequest struct {
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

type UpsertPermissionsRequest struct {
	Permissions map[string]int `json:"permissions" binding:"required"`
}
