package permgorm

import "gorm.io/gorm"

// Migrate runs AutoMigrate for all permissions tables.
// Call this after connecting your DB and before starting the HTTP server.
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&RoleModel{},
		&PermissionTypeModel{},
		&RolePermissionModel{},
		&UserPermissionModel{},
	)
}
