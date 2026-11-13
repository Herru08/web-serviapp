package storage

import (
	"database/sql"
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
