package storage

import (
	"database/sql"
	"io/ioutil"
	"log"
	_ "modernc.org/sqlite"
	"path/filepath"
)

func NewSQLiteDB(filepath string) *sql.DB {
	db, err := sql.Open("sqlite", filepath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatalf("Error abriendo DB: %v", err)
	}
	if err = db.Ping(); err != nil {
		log.Fatalf("Error conectando a SQLite: %v", err)
	}
	db.SetMaxOpenConns(1)

	// Ejecutar migraciones al iniciar la base de datos
	if err = runMigrations(db); err != nil {
		log.Fatalf("Error ejecutando migraciones: %v", err)
	}

	return db
}

// runMigrations carga y ejecuta todos los archivos .sql dentro de la carpeta migrations.
func runMigrations(db *sql.DB) error {
	migrationsDir := "migrations"
	files, err := ioutil.ReadDir(migrationsDir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if f.IsDir() || filepath.Ext(f.Name()) != ".sql" {
			continue
		}
		path := filepath.Join(migrationsDir, f.Name())
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		if _, err = db.Exec(string(content)); err != nil {
			return err
		}
		if f.Name() == "002_create_roles.sql" {
			if err = ensureRoleDescription(db); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureRoleDescription(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(roles)`)
	if err != nil {
		return err
	}
	hasDescription := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == "descripcion" {
			hasDescription = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if hasDescription {
		return nil
	}
	_, err = db.Exec(`ALTER TABLE roles ADD COLUMN descripcion TEXT`)
	return err
}
