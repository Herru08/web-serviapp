package middlewares

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"serviturno-backend/pkg/security"
)

type contextKey string

const (
	userIDContextKey contextKey = "user_id"
	roleContextKey   contextKey = "rol"
)

func UserIDFromRequest(r *http.Request) (int, bool) {
	id, ok := r.Context().Value(userIDContextKey).(int)
	return id, ok && id > 0
}

func RoleFromRequest(r *http.Request) (string, bool) {
	role, ok := r.Context().Value(roleContextKey).(string)
	return role, ok && role != ""
}

func RequireAuthenticated(db *sql.DB, next http.Handler) http.Handler {
	return requireAccess(db, "", next)
}

func RequirePermission(db *sql.DB, permission string, next http.Handler) http.Handler {
	return requireAccess(db, permission, next)
}

func requireAccess(db *sql.DB, permission string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("jwt")
		if err != nil {
			http.Error(w, `{"error": "No autorizado."}`, http.StatusUnauthorized)
			return
		}

		claims, err := security.ValidateJWT(cookie.Value)
		if err != nil {
			http.Error(w, `{"error": "Sesión expirada"}`, http.StatusUnauthorized)
			return
		}

		userIDClaim, ok := claims["user_id"].(float64)
		if !ok || userIDClaim < 1 || userIDClaim > float64(^uint(0)>>1) || userIDClaim != float64(int(userIDClaim)) {
			writeJSONError(w, http.StatusUnauthorized, "Sesión inválida")
			return
		}
		userID := int(userIDClaim)
		var userRole string
		err = db.QueryRow(`SELECT COALESCE(r.nombre, 'Usuario Regular')
			FROM usuarios u
			LEFT JOIN usuario_rol ur ON ur.usuario_id = u.id
			LEFT JOIN roles r ON r.id = ur.rol_id
			WHERE u.id = ? AND u.activo = 1
			LIMIT 1`, userID).Scan(&userRole)
		if err == sql.ErrNoRows {
			writeJSONError(w, http.StatusUnauthorized, "Cuenta no encontrada o inactiva")
			return
		}
		if err != nil {
			log.Printf("auth: validar cuenta: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "Error interno")
			return
		}
		if permission != "" {
			var allowed bool
			err = db.QueryRow(`SELECT EXISTS (
				SELECT 1
				FROM usuario_rol ur
				JOIN rol_permiso rp ON rp.rol_id = ur.rol_id
				JOIN permisos p ON p.id = rp.permiso_id
				WHERE ur.usuario_id = ? AND p.codigo = ?
			)`, userID, permission).Scan(&allowed)
			if err != nil {
				log.Printf("auth: validar permiso %q: %v", permission, err)
				writeJSONError(w, http.StatusInternalServerError, "Error interno")
				return
			}
			if !allowed {
				writeJSONError(w, http.StatusForbidden, "Acceso denegado")
				return
			}
		}

		ctx := context.WithValue(r.Context(), userIDContextKey, userID)
		ctx = context.WithValue(ctx, roleContextKey, userRole)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func ParseAllowedOrigins(value string) (map[string]struct{}, error) {
	origins := make(map[string]struct{})
	for _, entry := range strings.Split(value, ",") {
		origin := strings.TrimSpace(entry)
		if origin == "" {
			continue
		}
		parsed, err := url.Parse(origin)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
			parsed.Host == "" || parsed.User != nil || parsed.Path != "" ||
			parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("origen permitido inválido: %q", origin)
		}
		origins[origin] = struct{}{}
	}
	if len(origins) == 0 {
		return nil, fmt.Errorf("SERVITURNO_ALLOWED_ORIGINS debe incluir al menos un origen explícito")
	}
	return origins, nil
}

func EnableCORS(next http.Handler, allowedOrigins map[string]struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		_, allowed := allowedOrigins[origin]
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			if !allowed {
				writeJSONError(w, http.StatusForbidden, "Origen no permitido")
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}

		if r.Method == "OPTIONS" {
			if origin == "" || !allowed {
				writeJSONError(w, http.StatusForbidden, "Origen no permitido")
				return
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodPost || r.Method == http.MethodPut ||
			r.Method == http.MethodPatch || r.Method == http.MethodDelete {
			if origin == "" || !allowed {
				writeJSONError(w, http.StatusForbidden, "Se requiere un origen de confianza")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
