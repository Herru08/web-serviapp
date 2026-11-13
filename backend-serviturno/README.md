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
