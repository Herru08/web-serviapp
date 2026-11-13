CREATE TABLE IF NOT EXISTS usuario_rol (
    usuario_id INTEGER NOT NULL,
    rol_id INTEGER NOT NULL,
    PRIMARY KEY (usuario_id, rol_id),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    FOREIGN KEY (rol_id) REFERENCES roles(id) ON DELETE CASCADE
);
