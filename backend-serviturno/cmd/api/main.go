package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"serviturno-backend/internal/handlers"
	"serviturno-backend/internal/middlewares"
	"serviturno-backend/internal/storage"
	"serviturno-backend/pkg/security"
)

func main() {
	if err := security.ConfigureJWTSecret(os.Getenv("SERVITURNO_JWT_SECRET")); err != nil {
		log.Fatal(err)
	}
	allowedOrigins, err := middlewares.ParseAllowedOrigins(os.Getenv("SERVITURNO_ALLOWED_ORIGINS"))
	if err != nil {
		log.Fatal(err)
	}
	security.GenerateCertsIfNotExist()
	db := storage.NewSQLiteDB("serviturno.db")
	defer db.Close()

	mux := http.NewServeMux()
	authHandler := handlers.NewAuthHandler(db)
	adminHandler := handlers.NewAdminHandler(db)

	// API routes
	mux.HandleFunc("/api/auth/login", authHandler.Login)
	mux.HandleFunc("/api/auth/register", authHandler.Register)
	mux.Handle("/api/auth/change-password", middlewares.RequireRole("", http.HandlerFunc(authHandler.ChangePassword)))
	mux.HandleFunc("/api/auth/logout", authHandler.Logout)
	mux.Handle("/api/auth/me", middlewares.RequireRole("", http.HandlerFunc(authHandler.Me)))
	mux.HandleFunc("/api/public/stats", adminHandler.GetStats)

	mux.Handle("/api/admin/usuarios", middlewares.RequireRole("Administrador", http.HandlerFunc(adminHandler.GetUsuarios)))
	mux.Handle("/api/admin/usuarios/crear", middlewares.RequireRole("Administrador", http.HandlerFunc(adminHandler.CrearUsuario)))
	mux.Handle("/api/admin/usuarios/ban", middlewares.RequireRole("Administrador", http.HandlerFunc(adminHandler.ToggleBanUsuario)))
	mux.Handle("/api/admin/usuarios/delete", middlewares.RequireRole("Administrador", http.HandlerFunc(adminHandler.DeleteUsuario)))
	mux.Handle("/api/admin/roles", middlewares.RequireRole("Administrador", http.HandlerFunc(adminHandler.GetRoles)))
	mux.Handle("/api/admin/usuarios/rol", middlewares.RequireRole("Administrador", http.HandlerFunc(adminHandler.AsignarRol)))
	mux.Handle("/api/admin/auditoria", middlewares.RequireRole("Administrador", http.HandlerFunc(adminHandler.GetAuditoria)))
	mux.Handle("/api/admin/negocios/pendientes", middlewares.RequireRole("Administrador", http.HandlerFunc(adminHandler.GetNegociosPendientes)))
	mux.Handle("/api/admin/negocios/aprobar", middlewares.RequireRole("Administrador", http.HandlerFunc(adminHandler.AprobarNegocio)))
	mux.Handle("/api/admin/negocios", middlewares.RequireRole("Administrador", http.HandlerFunc(adminHandler.GestorNegocios)))
	mux.Handle("/api/admin/stats", middlewares.RequireRole("Administrador", http.HandlerFunc(adminHandler.GetStats)))

	// Serve static frontend files (relative to this file)
	frontendPath, _ := filepath.Abs("../frontend-serviturno")
	fs := http.FileServer(http.Dir(frontendPath))
	mux.Handle("/", fs) // catch‑all serves index.html, etc.

	handler := middlewares.EnableCORS(mux, allowedOrigins)

	log.Println("🚀 Servidor HTTPS seguro corriendo en https://localhost:8443")
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", handler))
}
