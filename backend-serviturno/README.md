# Configuración del backend

El servidor requiere una clave JWT y una lista explícita de orígenes frontend confiables. No guardes estos valores en el repositorio.

En PowerShell, desde `backend-serviturno`, puedes generar una clave aleatoria y arrancar en desarrollo así:

```powershell
$bytes = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$env:SERVITURNO_JWT_SECRET = [Convert]::ToBase64String($bytes)
$env:SERVITURNO_ALLOWED_ORIGINS = "https://localhost:8443,http://127.0.0.1:5501"
go run ./cmd/api
```

Incluye en `SERVITURNO_ALLOWED_ORIGINS` únicamente los orígenes exactos desde los que se sirve el frontend, separados por comas (esquema, host y puerto; sin rutas). Si usas Live Server en otro puerto, agrega su origen. En producción, configura ambas variables en el gestor de secretos/entorno del servicio y usa exclusivamente el dominio HTTPS real.

La clave JWT debe ser aleatoria y mantenerse igual entre reinicios e instancias. Rotarla invalida las sesiones existentes. Cambiar una contraseña requiere una sesión válida y la contraseña actual; la recuperación por correo no está habilitada hasta integrar un flujo de verificación de identidad.

## Roles y permisos

Las migraciones crean el catálogo de permisos y su relación con los roles. El rol `Administrador` recibe todos los permisos existentes; las cuentas sin rol reciben `Usuario Regular`. Los permisos se consultan desde la base de datos en cada petición protegida, por lo que un cambio de rol, la revocación de un permiso o la suspensión de una cuenta se aplica sin esperar a que caduque el JWT.

Los roles y sus permisos se administran desde **Usuarios y roles** en el panel. El rol `Administrador` no se puede eliminar ni degradar, y un rol asignado a usuarios no se puede eliminar. Para asignar un rol con permisos o crear usuarios con roles privilegiados se necesita `roles.gestionar`.

Permisos disponibles:

- `dashboard.leer`: resumen y estadísticas.
- `usuarios.leer`, `usuarios.crear`, `usuarios.gestionar`: consulta, creación, suspensión, reactivación y eliminación de usuarios.
- `roles.leer`, `roles.gestionar`: consulta y administración de roles y permisos.
- `negocios.leer`, `negocios.gestionar`: consulta y administración de negocios.
- `auditoria.leer`: consulta del registro de auditoría.
