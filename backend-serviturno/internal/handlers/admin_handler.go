package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

type AdminHandler struct{ DB *sql.DB }

func NewAdminHandler(db *sql.DB) *AdminHandler { return &AdminHandler{DB: db} }

// ---------- helpers ----------

func adminJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("admin: error escribiendo respuesta: %v", err)
	}
}

func adminError(w http.ResponseWriter, status int, msg string) {
	adminJSON(w, status, map[string]string{"error": msg})
}

// adminDBError registra el detalle en el log del servidor y devuelve un mensaje genérico al cliente.
func adminDBError(w http.ResponseWriter, op string, err error) {
	log.Printf("admin: %s: %v", op, err)
	adminError(w, http.StatusInternalServerError, "Error interno de base de datos")
}

func adminDecode(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		adminError(w, http.StatusBadRequest, "Datos inválidos")
		return false
	}
	return true
}

// ---------- auditoría ----------

func (h *AdminHandler) GetAuditoria(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(`SELECT a.id, u.correo, a.fecha_hora, a.direccion_ip, a.accion FROM audit_logs a LEFT JOIN usuarios u ON a.usuario_id = u.id ORDER BY a.fecha_hora DESC LIMIT 50`)
	if err != nil {
		adminDBError(w, "GetAuditoria", err)
		return
	}
	defer rows.Close()

	// make(...) evita que una lista vacía se serialice como null y rompa el front.
	logs := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id int
		var correo, fecha, ip, accion sql.NullString
		if err := rows.Scan(&id, &correo, &fecha, &ip, &accion); err != nil {
			log.Printf("admin: GetAuditoria scan: %v", err)
			continue
		}
		logs = append(logs, map[string]interface{}{"id": id, "correo": correo.String, "fecha": fecha.String, "ip": ip.String, "accion": accion.String})
	}
	if err := rows.Err(); err != nil {
		adminDBError(w, "GetAuditoria rows", err)
		return
	}
	adminJSON(w, http.StatusOK, logs)
}

// ---------- roles y usuarios ----------

func (h *AdminHandler) GetRoles(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(`SELECT id, nombre FROM roles ORDER BY id`)
	if err != nil {
		adminDBError(w, "GetRoles", err)
		return
	}
	defer rows.Close()

	roles := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id int
		var nombre string
		if err := rows.Scan(&id, &nombre); err != nil {
			log.Printf("admin: GetRoles scan: %v", err)
			continue
		}
		roles = append(roles, map[string]interface{}{"id": id, "nombre": nombre})
	}
	if err := rows.Err(); err != nil {
		adminDBError(w, "GetRoles rows", err)
		return
	}
	adminJSON(w, http.StatusOK, roles)
}

func (h *AdminHandler) AsignarRol(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UsuarioID int `json:"UsuarioID"`
		RolID     int `json:"RolID"`
	}
	if !adminDecode(w, r, &req) {
		return
	}
	if req.UsuarioID <= 0 || req.RolID <= 0 {
		adminError(w, http.StatusBadRequest, "UsuarioID y RolID son obligatorios")
		return
	}

	// Transacción: si el INSERT falla, no se pierde el rol anterior del usuario.
	tx, err := h.DB.Begin()
	if err != nil {
		adminDBError(w, "AsignarRol begin", err)
		return
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM usuario_rol WHERE usuario_id = ?`, req.UsuarioID); err != nil {
		adminDBError(w, "AsignarRol delete", err)
		return
	}
	if _, err := tx.Exec(`INSERT INTO usuario_rol (usuario_id, rol_id) VALUES (?, ?)`, req.UsuarioID, req.RolID); err != nil {
		adminDBError(w, "AsignarRol insert", err)
		return
	}
	if err := tx.Commit(); err != nil {
		adminDBError(w, "AsignarRol commit", err)
		return
	}
	adminJSON(w, http.StatusOK, map[string]string{"mensaje": "Rol actualizado"})
}

func (h *AdminHandler) GetUsuarios(w http.ResponseWriter, r *http.Request) {
    rows, err := h.DB.Query(`SELECT u.id, u.nombre, u.correo, COALESCE(u.activo, 1), IFNULL(r.nombre, 'Usuario Regular') as rol FROM usuarios u LEFT JOIN usuario_rol ur ON u.id = ur.usuario_id LEFT JOIN roles r ON ur.rol_id = r.id ORDER BY u.id`)
    if err != nil {
        adminDBError(w, "GetUsuarios", err)
        return
    }
    defer rows.Close()

    usuarios := make([]map[string]interface{}, 0)
    for rows.Next() {
        var id int
        var activo bool
        var nombre, correo, rol sql.NullString
        if err := rows.Scan(&id, &nombre, &correo, &activo, &rol); err != nil {
            log.Printf("admin: GetUsuarios scan: %v", err)
            continue
        }
        usuarios = append(usuarios, map[string]interface{}{"id": id, "nombre": nombre.String, "correo": correo.String, "activo": activo, "rol": rol.String})
    }
    if err := rows.Err(); err != nil {
        adminDBError(w, "GetUsuarios rows", err)
        return
    }
    adminJSON(w, http.StatusOK, usuarios)
}

// ---------- stats ----------

// GetStats returns quick statistics for the admin dashboard.
func (h *AdminHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		adminError(w, http.StatusMethodNotAllowed, "Método no permitido")
		return
	}

    var usuariosActivos int
    err := h.DB.QueryRow(`SELECT COUNT(*) FROM usuarios WHERE activo = 1`).Scan(&usuariosActivos)
    if err != nil {
        adminDBError(w, "GetStats usuarios", err)
        return
    }
	var negociosPublicados *int
	var totalNegocios int
	err = h.DB.QueryRow(`SELECT COUNT(*) FROM negocios WHERE estado = 'APROBADO'`).Scan(&totalNegocios)
    if err != nil {
		log.Printf("admin: GetStats negocios: %v", err)
	} else {
		negociosPublicados = &totalNegocios
    }
	adminJSON(w, http.StatusOK, map[string]interface{}{"usuarios": usuariosActivos, "negocios": negociosPublicados})
}

func (h *AdminHandler) ToggleBanUsuario(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UsuarioID int `json:"usuario_id"`
	}
	if !adminDecode(w, r, &req) {
		return
	}
	if req.UsuarioID <= 0 {
		adminError(w, http.StatusBadRequest, "usuario_id es obligatorio")
		return
	}

	res, err := h.DB.Exec(`UPDATE usuarios SET activo = NOT activo WHERE id = ?`, req.UsuarioID)
	if err != nil {
		adminDBError(w, "ToggleBanUsuario", err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		adminError(w, http.StatusNotFound, "Usuario no encontrado")
		return
	}
	adminJSON(w, http.StatusOK, map[string]string{"mensaje": "Estado de cuenta actualizado"})
}

func (h *AdminHandler) DeleteUsuario(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UsuarioID int `json:"usuario_id"`
	}
	if !adminDecode(w, r, &req) {
		return
	}
	if req.UsuarioID <= 0 {
		adminError(w, http.StatusBadRequest, "usuario_id es obligatorio")
		return
	}

	// Con negocios, tickets o reseñas ligados, borrar rompería datos (y falla si las FK están activas).
	var negs, tks, rvs int
	if err := h.DB.QueryRow(`SELECT (SELECT COUNT(*) FROM negocios WHERE usuario_id = ?), (SELECT COUNT(*) FROM tickets WHERE usuario_id = ?), (SELECT COUNT(*) FROM resenas WHERE usuario_id = ?)`,
		req.UsuarioID, req.UsuarioID, req.UsuarioID).Scan(&negs, &tks, &rvs); err != nil {
		adminDBError(w, "DeleteUsuario deps", err)
		return
	}
	if negs+tks+rvs > 0 {
		adminError(w, http.StatusConflict, "No se puede borrar: el usuario tiene negocios, tickets o reseñas asociados. Suspéndelo en su lugar.")
		return
	}

	tx, err := h.DB.Begin()
	if err != nil {
		adminDBError(w, "DeleteUsuario begin", err)
		return
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM usuario_rol WHERE usuario_id = ?`, req.UsuarioID); err != nil {
		adminDBError(w, "DeleteUsuario usuario_rol", err)
		return
	}
	// OJO: esto borra la trazabilidad del usuario. Ver recomendación en las notas (usar SET NULL).
	if _, err := tx.Exec(`DELETE FROM audit_logs WHERE usuario_id = ?`, req.UsuarioID); err != nil {
		adminDBError(w, "DeleteUsuario audit_logs", err)
		return
	}
	res, err := tx.Exec(`DELETE FROM usuarios WHERE id = ?`, req.UsuarioID)
	if err != nil {
		adminDBError(w, "DeleteUsuario usuarios", err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		adminError(w, http.StatusNotFound, "Usuario no encontrado")
		return
	}
	if err := tx.Commit(); err != nil {
		adminDBError(w, "DeleteUsuario commit", err)
		return
	}
	adminJSON(w, http.StatusOK, map[string]string{"mensaje": "Usuario eliminado"})
}

// ---------- negocios ----------

func (h *AdminHandler) GetNegociosPendientes(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(`SELECT id, nombre, categoria, telefono, direccion FROM negocios WHERE estado = 'PENDIENTE' ORDER BY id`)
	if err != nil {
		adminDBError(w, "GetNegociosPendientes", err)
		return
	}
	defer rows.Close()

	n := make([]map[string]interface{}, 0)
	for rows.Next() {
		var id int
		var nombre, categoria, telefono, direccion sql.NullString
		if err := rows.Scan(&id, &nombre, &categoria, &telefono, &direccion); err != nil {
			log.Printf("admin: GetNegociosPendientes scan: %v", err)
			continue
		}
		n = append(n, map[string]interface{}{"id": id, "nombre": nombre.String, "categoria": categoria.String, "telefono": telefono.String, "direccion": direccion.String})
	}
	if err := rows.Err(); err != nil {
		adminDBError(w, "GetNegociosPendientes rows", err)
		return
	}
	adminJSON(w, http.StatusOK, n)
}

func (h *AdminHandler) AprobarNegocio(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NegocioID int    `json:"negocio_id"`
		Accion    string `json:"accion"`
	}
	if !adminDecode(w, r, &req) {
		return
	}
	req.Accion = strings.ToUpper(strings.TrimSpace(req.Accion))
	// Lista blanca: antes se escribía en "estado" cualquier texto que mandara el cliente.
	if req.NegocioID <= 0 || (req.Accion != "APROBADO" && req.Accion != "RECHAZADO") {
		adminError(w, http.StatusBadRequest, "Acción inválida")
		return
	}

	res, err := h.DB.Exec(`UPDATE negocios SET estado = ? WHERE id = ?`, req.Accion, req.NegocioID)
	if err != nil {
		adminDBError(w, "AprobarNegocio", err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		adminError(w, http.StatusNotFound, "Negocio no encontrado o sin cambios")
		return
	}
	adminJSON(w, http.StatusOK, map[string]string{"mensaje": "Estado actualizado"})
}

func validTelefono(t string) bool {
	if len(t) > 20 {
		return false
	}
	for _, c := range t {
		if !(c >= '0' && c <= '9') && !strings.ContainsRune(" +-()", c) {
			return false
		}
	}
	return true
}

func (h *AdminHandler) GestorNegocios(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rows, err := h.DB.Query(`SELECT id, nombre, categoria, telefono, latitud, longitud FROM negocios WHERE estado = 'APROBADO' ORDER BY nombre`)
		if err != nil {
			adminDBError(w, "GestorNegocios GET", err)
			return
		}
		defer rows.Close()

		n := make([]map[string]interface{}, 0)
		for rows.Next() {
			var id int
			var nom, cat, tel, lat, lon sql.NullString
			if err := rows.Scan(&id, &nom, &cat, &tel, &lat, &lon); err != nil {
				log.Printf("admin: GestorNegocios scan: %v", err)
				continue
			}
			n = append(n, map[string]interface{}{"id": id, "nombre": nom.String, "categoria": cat.String, "telefono": tel.String, "latitud": lat.String, "longitud": lon.String})
		}
		if err := rows.Err(); err != nil {
			adminDBError(w, "GestorNegocios rows", err)
			return
		}
		adminJSON(w, http.StatusOK, n)

	case http.MethodPost:
		var req struct {
			Nombre    string `json:"nombre"`
			Categoria string `json:"categoria"`
			Telefono  string `json:"telefono"`
			Direccion string `json:"direccion"`
			Ciudad    string `json:"ciudad"`
			Horario   string `json:"horario"`
			Descrip   string `json:"descripcion"`
			UsuarioID int    `json:"usuario_id"`
			Latitud   string `json:"latitud"`
			Longitud  string `json:"longitud"`
		}
		if !adminDecode(w, r, &req) {
			return
		}
		req.Nombre = strings.TrimSpace(req.Nombre)
		req.Categoria = strings.TrimSpace(req.Categoria)
		req.Telefono = strings.TrimSpace(req.Telefono)
		req.Direccion = strings.TrimSpace(req.Direccion)
		req.Ciudad = strings.TrimSpace(req.Ciudad)
		req.Horario = strings.TrimSpace(req.Horario)
		req.Descrip = strings.TrimSpace(req.Descrip)
		if req.Ciudad == "" {
			req.Ciudad = "Tuxtla Gutiérrez"
		}

		if req.Nombre == "" || req.Categoria == "" {
			adminError(w, http.StatusBadRequest, "Nombre y categoría son obligatorios")
			return
		}
		if utf8.RuneCountInString(req.Nombre) > 150 || utf8.RuneCountInString(req.Categoria) > 80 || utf8.RuneCountInString(req.Direccion) > 255 ||
			utf8.RuneCountInString(req.Ciudad) > 100 || utf8.RuneCountInString(req.Horario) > 100 || utf8.RuneCountInString(req.Descrip) > 500 {
			adminError(w, http.StatusBadRequest, "Alguno de los campos es demasiado largo")
			return
		}
		if !validTelefono(req.Telefono) {
			adminError(w, http.StatusBadRequest, "Teléfono inválido")
			return
		}

		lat, errLat := strconv.ParseFloat(strings.TrimSpace(req.Latitud), 64)
		lng, errLng := strconv.ParseFloat(strings.TrimSpace(req.Longitud), 64)
		if errLat != nil || errLng != nil ||
			math.IsNaN(lat) || math.IsInf(lat, 0) || math.IsNaN(lng) || math.IsInf(lng, 0) ||
			lat < -90 || lat > 90 || lng < -180 || lng > 180 {
			adminError(w, http.StatusBadRequest, "Ubicación inválida: selecciona un punto en el mapa")
			return
		}

		// Dueño opcional: sin dueño, el negocio queda con usuario_id NULL.
		var dueno interface{}
		if req.UsuarioID > 0 {
			var n int
			if err := h.DB.QueryRow(`SELECT COUNT(*) FROM usuarios WHERE id = ?`, req.UsuarioID).Scan(&n); err != nil {
				adminDBError(w, "GestorNegocios dueño", err)
				return
			}
			if n == 0 {
				adminError(w, http.StatusBadRequest, "El dueño seleccionado no existe")
				return
			}
			dueno = req.UsuarioID
		}

		_, err := h.DB.Exec(`INSERT INTO negocios (usuario_id, nombre, categoria, descripcion, telefono, direccion, ciudad, horario, latitud, longitud, estado, abierto, creado_en) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'APROBADO', 1, ?)`,
			dueno, req.Nombre, req.Categoria, req.Descrip, req.Telefono, req.Direccion, req.Ciudad, req.Horario,
			strconv.FormatFloat(lat, 'f', 6, 64), strconv.FormatFloat(lng, 'f', 6, 64),
			time.Now().Format("2006-01-02 15:04:05"))
		if err != nil {
			// Antes se devolvía err.Error() dentro de un JSON armado a mano: filtraba datos internos y podía romper el JSON.
			adminDBError(w, "GestorNegocios POST", err)
			return
		}
		adminJSON(w, http.StatusCreated, map[string]string{"mensaje": "Negocio registrado exitosamente"})

	default:
		w.Header().Set("Allow", "GET, POST")
		adminError(w, http.StatusMethodNotAllowed, "Método no permitido")
	}
}

// ---------- alta de usuarios ----------

// CrearUsuario: POST /admin/usuarios/crear
// Crea la cuenta ya verificada y activa, con el rol elegido, en una sola transacción.
func (h *AdminHandler) CrearUsuario(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		adminError(w, http.StatusMethodNotAllowed, "Método no permitido")
		return
	}
	var req struct {
		Nombre    string `json:"nombre"`
		Apellidos string `json:"apellidos"`
		Correo    string `json:"correo"`
		Telefono  string `json:"telefono"`
		Password  string `json:"password"`
		RolID     int    `json:"rol_id"`
	}
	if !adminDecode(w, r, &req) {
		return
	}
	req.Nombre = strings.TrimSpace(req.Nombre)
	req.Apellidos = strings.TrimSpace(req.Apellidos)
	req.Correo = strings.ToLower(strings.TrimSpace(req.Correo))
	req.Telefono = strings.TrimSpace(req.Telefono)

	if req.Nombre == "" || utf8.RuneCountInString(req.Nombre) > 120 || utf8.RuneCountInString(req.Apellidos) > 120 {
		adminError(w, http.StatusBadRequest, "Nombre obligatorio (máx. 120 caracteres)")
		return
	}
	if addr, err := mail.ParseAddress(req.Correo); err != nil || addr.Address != req.Correo || len(req.Correo) > 150 {
		adminError(w, http.StatusBadRequest, "Correo inválido")
		return
	}
	if !validTelefono(req.Telefono) {
		adminError(w, http.StatusBadRequest, "Teléfono inválido")
		return
	}
	if len(req.Password) < 8 || len(req.Password) > 72 { // bcrypt solo usa los primeros 72 bytes
		adminError(w, http.StatusBadRequest, "La contraseña debe tener entre 8 y 72 caracteres")
		return
	}
	if req.RolID <= 0 {
		adminError(w, http.StatusBadRequest, "Selecciona un rol")
		return
	}

	var existe int
	if err := h.DB.QueryRow(`SELECT COUNT(*) FROM usuarios WHERE LOWER(correo) = ?`, req.Correo).Scan(&existe); err != nil {
		adminDBError(w, "CrearUsuario check", err)
		return
	}
	if existe > 0 {
		adminError(w, http.StatusConflict, "Ya existe un usuario con ese correo")
		return
	}
	var rolOK int
	if err := h.DB.QueryRow(`SELECT COUNT(*) FROM roles WHERE id = ?`, req.RolID).Scan(&rolOK); err != nil {
		adminDBError(w, "CrearUsuario rol", err)
		return
	}
	if rolOK == 0 {
		adminError(w, http.StatusBadRequest, "El rol seleccionado no existe")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12) // mismo costo que los hashes existentes
	if err != nil {
		adminDBError(w, "CrearUsuario hash", err)
		return
	}

	var tel, ape interface{}
	if req.Telefono != "" {
		tel = req.Telefono
	}
	if req.Apellidos != "" {
		ape = req.Apellidos
	}

	tx, err := h.DB.Begin()
	if err != nil {
		adminDBError(w, "CrearUsuario begin", err)
		return
	}
	defer tx.Rollback()

	res, err := tx.Exec(`INSERT INTO usuarios (nombre, apellidos, correo, telefono, password_hash, creado_en, email_verificado, activo, intentos_fallidos, notif_tickets, notif_recordatorios, notif_promociones) VALUES (?, ?, ?, ?, ?, ?, 1, 1, 0, 1, 1, 0)`,
		req.Nombre, ape, req.Correo, tel, string(hash), time.Now().Format("2006-01-02 15:04:05"))
	if err != nil {
		if strings.Contains(strings.ToUpper(err.Error()), "UNIQUE") {
			adminError(w, http.StatusConflict, "Ya existe un usuario con ese correo")
			return
		}
		adminDBError(w, "CrearUsuario insert", err)
		return
	}
	id, err := res.LastInsertId()
	if err != nil {
		adminDBError(w, "CrearUsuario id", err)
		return
	}
	if _, err := tx.Exec(`INSERT INTO usuario_rol (usuario_id, rol_id) VALUES (?, ?)`, id, req.RolID); err != nil {
		adminDBError(w, "CrearUsuario rol", err)
		return
	}
	if err := tx.Commit(); err != nil {
		adminDBError(w, "CrearUsuario commit", err)
		return
	}
	adminJSON(w, http.StatusCreated, map[string]interface{}{"mensaje": "Usuario creado", "id": id})
}
