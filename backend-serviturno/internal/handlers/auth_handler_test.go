package handlers_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
	"serviturno-backend/internal/handlers"
	"serviturno-backend/internal/middlewares"
	"serviturno-backend/pkg/security"
)

func TestChangePasswordRequiresCurrentPasswordAndSession(t *testing.T) {
	if err := security.ConfigureJWTSecret("handler-test-signing-key-with-32-bytes"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE usuarios (id INTEGER PRIMARY KEY, password_hash TEXT NOT NULL, activo INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	oldHash, err := security.HashPassword("correct-old-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO usuarios (id, password_hash, activo) VALUES (1, ?, 1)`, oldHash); err != nil {
		t.Fatal(err)
	}

	authHandler := handlers.NewAuthHandler(db)
	handler := middlewares.RequireRole("", http.HandlerFunc(authHandler.ChangePassword))
	token, err := security.GenerateJWT(1, "Usuario Regular")
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/auth/change-password",
		strings.NewReader(`{"current_password":"wrong-password","nueva_password":"new-password-123"}`))
	request.AddCookie(&http.Cookie{Name: "jwt", Value: token})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current password status = %d, want %d", response.Code, http.StatusUnauthorized)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/auth/change-password",
		strings.NewReader(`{"current_password":"correct-old-password","nueva_password":"new-password-123"}`))
	request.AddCookie(&http.Cookie{Name: "jwt", Value: token})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid password change status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}

	var newHash string
	if err := db.QueryRow(`SELECT password_hash FROM usuarios WHERE id = 1`).Scan(&newHash); err != nil {
		t.Fatal(err)
	}
	if !security.CheckPasswordHash("new-password-123", newHash) {
		t.Fatal("new password was not saved")
	}

	request = httptest.NewRequest(http.MethodPost, "/api/auth/change-password",
		strings.NewReader(`{"current_password":"correct-old-password","nueva_password":"another-password-123"}`))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("request without session status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}
