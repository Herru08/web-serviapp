package middlewares

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"serviturno-backend/pkg/security"
	"strings"
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

func RequireRole(requiredRole string, next http.Handler) http.Handler {
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

		userRole, ok := claims["rol"].(string)
		if !ok || userRole == "" {
			writeJSONError(w, http.StatusUnauthorized, "Sesión inválida")
			return
		}
		if requiredRole != "" && userRole != requiredRole && userRole != "Administrador" {
			writeJSONError(w, http.StatusForbidden, "Acceso denegado")
			return
		}

		userIDClaim, ok := claims["user_id"].(float64)
		if !ok || userIDClaim < 1 || userIDClaim > float64(^uint(0)>>1) {
			writeJSONError(w, http.StatusUnauthorized, "Sesión inválida")
			return
		}
		ctx := context.WithValue(r.Context(), userIDContextKey, int(userIDClaim))
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
