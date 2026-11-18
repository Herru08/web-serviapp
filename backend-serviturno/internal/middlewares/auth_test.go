package middlewares

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "modernc.org/sqlite"
	"serviturno-backend/pkg/security"
)

func TestParseAllowedOriginsRequiresExplicitOrigins(t *testing.T) {
	for _, value := range []string{"", " ", "*", "https://example.com/path", "file://example.com"} {
		if _, err := ParseAllowedOrigins(value); err == nil {
			t.Errorf("ParseAllowedOrigins(%q) succeeded, want error", value)
		}
	}

	origins, err := ParseAllowedOrigins("https://app.example.com, http://localhost:5501")
	if err != nil {
		t.Fatal(err)
	}
	if len(origins) != 2 {
		t.Fatalf("got %d origins, want 2", len(origins))
	}
}

func TestCORSRestrictsOriginsAndUnsafeRequests(t *testing.T) {
	allowedOrigins, err := ParseAllowedOrigins("https://app.example.com")
	if err != nil {
		t.Fatal(err)
	}

	called := false
	handler := EnableCORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}), allowedOrigins)

	tests := []struct {
		name       string
		method     string
		origin     string
		wantStatus int
		wantCalled bool
	}{
		{name: "trusted write", method: http.MethodPost, origin: "https://app.example.com", wantStatus: http.StatusNoContent, wantCalled: true},
		{name: "untrusted write", method: http.MethodPost, origin: "https://evil.example", wantStatus: http.StatusForbidden},
		{name: "write without origin", method: http.MethodPost, wantStatus: http.StatusForbidden},
		{name: "untrusted read", method: http.MethodGet, origin: "https://evil.example", wantStatus: http.StatusForbidden},
		{name: "trusted preflight", method: http.MethodOptions, origin: "https://app.example.com", wantStatus: http.StatusNoContent},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called = false
			request := httptest.NewRequest(test.method, "/api/test", nil)
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if called != test.wantCalled {
				t.Fatalf("next handler called = %v, want %v", called, test.wantCalled)
			}
			if test.origin == "https://evil.example" && response.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("untrusted origin received Access-Control-Allow-Origin")
			}
		})
	}
}

func TestRequirePermissionUsesCurrentDatabasePermissions(t *testing.T) {
	if err := security.ConfigureJWTSecret("permission-test-signing-key-with-32-bytes"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
		CREATE TABLE usuarios (id INTEGER PRIMARY KEY, activo INTEGER NOT NULL);
		CREATE TABLE roles (id INTEGER PRIMARY KEY, nombre TEXT NOT NULL);
		CREATE TABLE usuario_rol (usuario_id INTEGER NOT NULL, rol_id INTEGER NOT NULL);
		CREATE TABLE permisos (id INTEGER PRIMARY KEY, codigo TEXT NOT NULL);
		CREATE TABLE rol_permiso (rol_id INTEGER NOT NULL, permiso_id INTEGER NOT NULL);
		INSERT INTO usuarios VALUES (1, 1);
		INSERT INTO roles VALUES (1, 'Administrador');
		INSERT INTO usuario_rol VALUES (1, 1);
		INSERT INTO permisos VALUES (1, 'usuarios.leer');
		INSERT INTO rol_permiso VALUES (1, 1);
	`)
	if err != nil {
		t.Fatal(err)
	}
	token, err := security.GenerateJWT(1, "Administrador")
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	requestFor := func(handler http.Handler) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, "/api/admin/usuarios", nil)
		request.AddCookie(&http.Cookie{Name: "jwt", Value: token})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	allowed := requestFor(RequirePermission(db, "usuarios.leer", next))
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("granted permission status = %d, want %d", allowed.Code, http.StatusNoContent)
	}
	denied := requestFor(RequirePermission(db, "roles.gestionar", next))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("missing permission status = %d, want %d", denied.Code, http.StatusForbidden)
	}

	if _, err := db.Exec(`DELETE FROM rol_permiso WHERE rol_id = 1`); err != nil {
		t.Fatal(err)
	}
	revoked := requestFor(RequirePermission(db, "usuarios.leer", next))
	if revoked.Code != http.StatusForbidden {
		t.Fatalf("revoked permission status = %d, want %d", revoked.Code, http.StatusForbidden)
	}

	if _, err := db.Exec(`UPDATE usuarios SET activo = 0 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	inactive := requestFor(RequirePermission(db, "usuarios.leer", next))
	if inactive.Code != http.StatusUnauthorized {
		t.Fatalf("inactive user status = %d, want %d", inactive.Code, http.StatusUnauthorized)
	}
}
