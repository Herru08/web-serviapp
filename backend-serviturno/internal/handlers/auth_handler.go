package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"serviturno-backend/internal/middlewares"
	"serviturno-backend/pkg/security"
)

type AuthHandler struct{ DB *sql.DB }

func NewAuthHandler(db *sql.DB) *AuthHandler { return &AuthHandler{DB: db} }

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct{ Correo, Password string }
	json.NewDecoder(r.Body).Decode(&req)

	var id, intentos int
	var passwordHash string
	var activo bool
	var rolNombre, bloqueadoHasta sql.NullString

	query := `SELECT u.id, u.password_hash, u.activo, u.intentos_fallidos, u.bloqueado_hasta, r.nombre 
			  FROM usuarios u LEFT JOIN usuario_rol ur ON u.id = ur.usuario_id LEFT JOIN roles r ON ur.rol_id = r.id WHERE u.correo = ?`
	err := h.DB.QueryRow(query, req.Correo).Scan(&id, &passwordHash, &activo, &intentos, &bloqueadoHasta, &rolNombre)

	if err == sql.ErrNoRows {
		http.Error(w, `{"error": "Credenciales incorrectas"}`, http.StatusUnauthorized)
		return
	}
	if !activo {
		http.Error(w, `{"error": "Cuenta bloqueada"}`, http.StatusForbidden)
		return
	}
	if bloqueadoHasta.Valid {
		blockTime, _ := time.Parse("2006-01-02 15:04:05", bloqueadoHasta.String)
		if time.Now().Before(blockTime) {
			http.Error(w, `{"error": "Demasiados intentos fallidos. Bloqueado."}`, http.StatusTooManyRequests)
			return
		}
	}

	if !security.CheckPasswordHash(req.Password, passwordHash) {
		intentos++
		if intentos >= 3 {
			h.DB.Exec(`UPDATE usuarios SET intentos_fallidos = ?, bloqueado_hasta = ? WHERE id = ?`, intentos, time.Now().Add(15*time.Minute).Format("2006-01-02 15:04:05"), id)
		} else {
			h.DB.Exec(`UPDATE usuarios SET intentos_fallidos = ? WHERE id = ?`, intentos, id)
		}
		http.Error(w, `{"error": "Credenciales incorrectas"}`, http.StatusUnauthorized)
		return
	}

	h.DB.Exec(`UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?`, id)

	rol := "Usuario Regular"
	if rolNombre.Valid {
		rol = rolNombre.String
	}

	token, err := security.GenerateJWT(id, rol)
	if err != nil {
		http.Error(w, `{"error": "No se pudo iniciar sesión"}`, http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "jwt", Value: token, Expires: time.Now().Add(15 * time.Minute),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode, Path: "/",
	})

	h.DB.Exec(`INSERT INTO audit_logs (usuario_id, fecha_hora, direccion_ip, accion) VALUES (?, ?, ?, ?)`, id, time.Now().Format("2006-01-02 15:04:05"), r.RemoteAddr, "Inicio de sesión")

	json.NewEncoder(w).Encode(map[string]string{"mensaje": "OK", "rol": rol})
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, `{"error": "Método no permitido"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct{ Nombre, Correo, Password string }
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, `{"error": "Datos inválidos"}`, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Nombre) == "" || strings.TrimSpace(req.Correo) == "" || len(req.Password) < 8 || len(req.Password) > 72 {
		http.Error(w, `{"error": "Nombre, correo y contraseña válida son obligatorios"}`, http.StatusBadRequest)
		return
	}
	hash, err := security.HashPassword(req.Password)
	if err != nil {
		log.Printf("auth: Register hash: %v", err)
		http.Error(w, `{"error": "No se pudo crear la cuenta"}`, http.StatusInternalServerError)
		return
	}
	tx, err := h.DB.Begin()
	if err != nil {
		log.Printf("auth: Register begin: %v", err)
		http.Error(w, `{"error": "No se pudo crear la cuenta"}`, http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO usuarios (nombre, correo, password_hash, activo, creado_en) VALUES (?, ?, ?, 1, ?)`, strings.TrimSpace(req.Nombre), strings.TrimSpace(req.Correo), hash, time.Now().Format("2006-01-02 15:04:05"))
	if err != nil {
		if strings.Contains(strings.ToUpper(err.Error()), "UNIQUE") {
			http.Error(w, `{"error": "El correo ya está registrado"}`, http.StatusConflict)
			return
		}
		log.Printf("auth: Register insert: %v", err)
		http.Error(w, `{"error": "No se pudo crear la cuenta"}`, http.StatusInternalServerError)
		return
	}
	id, err := result.LastInsertId()
	if err != nil {
		log.Printf("auth: Register id: %v", err)
		http.Error(w, `{"error": "No se pudo crear la cuenta"}`, http.StatusInternalServerError)
		return
	}
	roleResult, err := tx.Exec(`INSERT INTO usuario_rol (usuario_id, rol_id)
		SELECT ?, id FROM roles WHERE nombre = 'Usuario Regular'`, id)
	if err != nil {
		log.Printf("auth: Register role: %v", err)
		http.Error(w, `{"error": "No se pudo asignar el rol inicial"}`, http.StatusInternalServerError)
		return
	}
	if affected, _ := roleResult.RowsAffected(); affected == 0 {
		http.Error(w, `{"error": "No existe el rol inicial de usuario"}`, http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("auth: Register commit: %v", err)
		http.Error(w, `{"error": "No se pudo crear la cuenta"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Registro exitoso"})
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, `{"error": "Método no permitido"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, ok := middlewares.UserIDFromRequest(r)
	if !ok {
		http.Error(w, `{"error": "No autorizado"}`, http.StatusUnauthorized)
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NuevaPassword   string `json:"nueva_password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, `{"error": "Datos inválidos"}`, http.StatusBadRequest)
		return
	}
	if len(req.NuevaPassword) < 8 || len(req.NuevaPassword) > 72 {
		http.Error(w, `{"error": "La contraseña debe tener entre 8 y 72 caracteres"}`, http.StatusBadRequest)
		return
	}
	var passwordHash string
	if err := h.DB.QueryRow(`SELECT password_hash FROM usuarios WHERE id = ? AND activo = 1`, userID).Scan(&passwordHash); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, `{"error": "Cuenta no encontrada o inactiva"}`, http.StatusNotFound)
			return
		}
		log.Printf("auth: ChangePassword lookup: %v", err)
		http.Error(w, `{"error": "Error interno"}`, http.StatusInternalServerError)
		return
	}
	if !security.CheckPasswordHash(req.CurrentPassword, passwordHash) {
		http.Error(w, `{"error": "La contraseña actual es incorrecta"}`, http.StatusUnauthorized)
		return
	}
	hash, err := security.HashPassword(req.NuevaPassword)
	if err != nil {
		log.Printf("auth: ChangePassword hash: %v", err)
		http.Error(w, `{"error": "No se pudo actualizar la contraseña"}`, http.StatusInternalServerError)
		return
	}
	if _, err := h.DB.Exec(`UPDATE usuarios SET password_hash = ? WHERE id = ?`, hash, userID); err != nil {
		log.Printf("auth: ChangePassword update: %v", err)
		http.Error(w, `{"error": "No se pudo actualizar la contraseña"}`, http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Contraseña actualizada"})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, `{"error": "Método no permitido"}`, http.StatusMethodNotAllowed)
		return
	}
	userID, ok := middlewares.UserIDFromRequest(r)
	if !ok {
		http.Error(w, `{"error": "No autorizado"}`, http.StatusUnauthorized)
		return
	}
	rol, _ := middlewares.RoleFromRequest(r)
	var nombre, correo string
	if err := h.DB.QueryRow(`SELECT nombre, correo FROM usuarios WHERE id = ?`, userID).Scan(&nombre, &correo); err != nil {
		log.Printf("auth: Me usuario: %v", err)
		http.Error(w, `{"error": "Error interno"}`, http.StatusInternalServerError)
		return
	}
	rows, err := h.DB.Query(`SELECT DISTINCT p.codigo
		FROM usuario_rol ur
		JOIN rol_permiso rp ON rp.rol_id = ur.rol_id
		JOIN permisos p ON p.id = rp.permiso_id
		WHERE ur.usuario_id = ?
		ORDER BY p.codigo`, userID)
	if err != nil {
		log.Printf("auth: Me permisos: %v", err)
		http.Error(w, `{"error": "Error interno"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	permisos := make([]string, 0)
	for rows.Next() {
		var permiso string
		if err := rows.Scan(&permiso); err != nil {
			log.Printf("auth: Me permisos scan: %v", err)
			http.Error(w, `{"error": "Error interno"}`, http.StatusInternalServerError)
			return
		}
		permisos = append(permisos, permiso)
	}
	if err := rows.Err(); err != nil {
		log.Printf("auth: Me permisos rows: %v", err)
		http.Error(w, `{"error": "Error interno"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"rol": rol, "nombre": nombre, "correo": correo, "permisos": permisos,
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "jwt", Value: "", Expires: time.Now().Add(-1 * time.Hour), HttpOnly: true, Secure: true, SameSite: http.SameSiteNoneMode, Path: "/"})
	json.NewEncoder(w).Encode(map[string]string{"mensaje": "Sesión cerrada"})
}
