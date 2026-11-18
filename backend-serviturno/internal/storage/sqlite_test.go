package storage

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestEnsureRoleDescriptionSupportsLegacySchema(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.Exec(`CREATE TABLE roles (id INTEGER PRIMARY KEY, nombre TEXT NOT NULL UNIQUE)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO roles (nombre) VALUES ('Administrador')`); err != nil {
		t.Fatal(err)
	}

	if err := ensureRoleDescription(db); err != nil {
		t.Fatalf("ensureRoleDescription() error = %v", err)
	}
	if err := ensureRoleDescription(db); err != nil {
		t.Fatalf("second ensureRoleDescription() error = %v", err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO roles (nombre, descripcion) VALUES
		('Administrador', 'Control total del sistema'),
		('Usuario Regular', 'Acceso básico de cliente')`); err != nil {
		t.Fatalf("seed roles migration error = %v", err)
	}

	var description sql.NullString
	if err := db.QueryRow(`SELECT descripcion FROM roles WHERE nombre = 'Administrador'`).Scan(&description); err != nil {
		t.Fatal(err)
	}
	if description.Valid {
		t.Fatalf("expected existing role description to remain NULL, got %q", description.String)
	}
	var roleCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM roles WHERE nombre = 'Usuario Regular'`).Scan(&roleCount); err != nil {
		t.Fatal(err)
	}
	if roleCount != 1 {
		t.Fatalf("expected seeded regular role, got %d matching roles", roleCount)
	}
}

func TestPermissionsMigrationSeedsCatalogAndDefaultRoles(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
		CREATE TABLE roles (id INTEGER PRIMARY KEY, nombre TEXT NOT NULL UNIQUE, descripcion TEXT);
		CREATE TABLE usuarios (id INTEGER PRIMARY KEY);
		CREATE TABLE usuario_rol (usuario_id INTEGER NOT NULL, rol_id INTEGER NOT NULL, PRIMARY KEY (usuario_id, rol_id));
		INSERT INTO roles VALUES (1, 'Administrador', 'Control total');
		INSERT INTO roles VALUES (2, 'Usuario Regular', 'Acceso básico');
		INSERT INTO usuarios VALUES (1);
		INSERT INTO usuarios VALUES (2);
		INSERT INTO usuario_rol VALUES (1, 1);
	`); err != nil {
		t.Fatal(err)
	}

	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations", "005_create_permisos.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(migration)); err != nil {
		t.Fatalf("apply permissions migration: %v", err)
	}
	if _, err := db.Exec(string(migration)); err != nil {
		t.Fatalf("reapply permissions migration: %v", err)
	}

	var permissionCount, adminPermissionCount, defaultRoleCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM permisos`).Scan(&permissionCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM rol_permiso WHERE rol_id = 1`).Scan(&adminPermissionCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM usuario_rol WHERE usuario_id = 2 AND rol_id = 2`).Scan(&defaultRoleCount); err != nil {
		t.Fatal(err)
	}
	if permissionCount != 9 || adminPermissionCount != permissionCount || defaultRoleCount != 1 {
		t.Fatalf("migration counts = permissions %d, admin grants %d, default assignments %d", permissionCount, adminPermissionCount, defaultRoleCount)
	}
}
