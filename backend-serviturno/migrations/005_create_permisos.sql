CREATE TABLE IF NOT EXISTS permisos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo TEXT NOT NULL UNIQUE,
    nombre TEXT NOT NULL,
    descripcion TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS rol_permiso (
    rol_id INTEGER NOT NULL,
    permiso_id INTEGER NOT NULL,
    PRIMARY KEY (rol_id, permiso_id),
    FOREIGN KEY (rol_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permiso_id) REFERENCES permisos(id) ON DELETE CASCADE
);

INSERT OR IGNORE INTO permisos (codigo, nombre, descripcion) VALUES
('dashboard.leer', 'Ver resumen', 'Consultar estadísticas del panel'),
('usuarios.leer', 'Consultar usuarios', 'Ver las cuentas registradas'),
('usuarios.crear', 'Crear usuarios', 'Registrar nuevas cuentas'),
('usuarios.gestionar', 'Gestionar usuarios', 'Suspender, reactivar y eliminar cuentas'),
('roles.leer', 'Consultar roles', 'Ver roles disponibles'),
('roles.gestionar', 'Gestionar roles y permisos', 'Crear roles y asignar permisos'),
('negocios.leer', 'Consultar negocios', 'Ver el directorio y el mapa'),
('negocios.gestionar', 'Gestionar negocios', 'Registrar, aprobar y rechazar negocios'),
('auditoria.leer', 'Consultar auditoría', 'Ver los movimientos registrados');

INSERT OR IGNORE INTO rol_permiso (rol_id, permiso_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permisos p
WHERE r.nombre = 'Administrador';

INSERT OR IGNORE INTO usuario_rol (usuario_id, rol_id)
SELECT u.id, r.id
FROM usuarios u CROSS JOIN roles r
WHERE r.nombre = 'Usuario Regular'
  AND NOT EXISTS (SELECT 1 FROM usuario_rol ur WHERE ur.usuario_id = u.id);
