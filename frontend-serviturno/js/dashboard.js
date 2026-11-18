// Requiere que la página cargue antes tu helper global api(path, options) y Leaflet (L).

let rolesCache = [];
let directorioCache = [];
let currentPermissions = new Set();
let permissionsCatalog = [];
let allowedSections = new Set();

const MAPA_CENTRO = [16.7533, -93.1165];
const TILE_URL = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png';
const TILE_ATTR = '&copy; OpenStreetMap';
const SECCIONES = {
    dashboard:  ['Resumen general', 'Estadísticas actuales de Serviturno'],
    negocios:   ['Negocios pendientes', 'Solicitudes esperando tu aprobación'],
    usuarios:   ['Usuarios y roles', 'Asigna roles, suspende o elimina cuentas'],
    directorio: ['Directorio y registro', 'Da de alta negocios y consulta los publicados'],
    mapa:       ['Mapa de negocios', 'Ubicación de todos los negocios aprobados'],
    auditoria:  ['Auditoría', 'Últimos 50 movimientos registrados en el sistema']
};
const PERMISO_SECCION = {
    dashboard: 'dashboard.leer',
    negocios: 'negocios.gestionar',
    directorio: 'negocios.leer',
    mapa: 'negocios.leer',
    usuarios: 'usuarios.leer',
    auditoria: 'auditoria.leer'
};
const PALETA = ['#2560AC', '#d97706', '#7c3aed', '#db2777', '#2563eb', '#65a30d', '#dc2626', '#0891b2'];

// Envoltorio de fetchAPI: si el servidor responde {"error": "..."} se trata como fallo,
// aunque fetchAPI no lance excepción. Así el panel nunca "simula" que guardó.
async function api(path, options) {
    const r = await fetchAPI(path, options);
    if (r && typeof r === 'object' && !Array.isArray(r) && r.error) throw new Error(r.error);
    return r;
}

// ---------- utilidades ----------
const $ = id => document.getElementById(id);
const asArray = x => Array.isArray(x) ? x : [];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const msgError = e => (e && e.message) ? e.message : 'Ocurrió un error inesperado';

function colorCategoria(cat) {
    let h = 0;
    for (const ch of String(cat || '')) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
    return PALETA[h % PALETA.length];
}
function esCoordValida(lat, lng) {
    return Number.isFinite(lat) && Number.isFinite(lng) &&
        Math.abs(lat) <= 90 && Math.abs(lng) <= 180 && !(lat === 0 && lng === 0);
}
function filaMensaje(cols, texto, clase = 'tabla-vacia') {
    return `<tr><td colspan="${cols}" class="${clase}">${esc(texto)}</td></tr>`;
}

let alertTimer;
function showAlert(msg, error = false) {
    const el = $('alertContainer');
    if (!el) return;
    el.textContent = msg;
    el.className = `toast ${error ? 'toast-error' : 'toast-ok'}`;
    clearTimeout(alertTimer);
    alertTimer = setTimeout(() => el.classList.add('hidden'), 5000);
}

// ---------- arranque ----------
document.addEventListener('DOMContentLoaded', async () => {
    try {
        const me = await api('/auth/me');
        currentPermissions = new Set(asArray(me.permisos));
        const nombre = me && (me.nombre || me.correo);
        if ($('adminNombre') && nombre) $('adminNombre').textContent = nombre;
    } catch (e) {
        window.location.href = 'login.html';
        return;
    }

    document.querySelectorAll('[data-nav]').forEach(button => {
        const section = button.dataset.nav;
        const allowed = currentPermissions.has(PERMISO_SECCION[section]);
        button.classList.toggle('hidden', !allowed);
        if (allowed) allowedSections.add(section);
    });
    const canReadBusinesses = currentPermissions.has('negocios.leer');
    const canManageBusinesses = currentPermissions.has('negocios.gestionar');
    $('btnDashboardNegocio').classList.toggle('hidden', !(canReadBusinesses && canManageBusinesses));
    const canReadRoles = currentPermissions.has('roles.leer');
    $('btnNuevoUsuario').classList.toggle('hidden', !(currentPermissions.has('usuarios.crear') && canReadRoles));
    if (!currentPermissions.has('usuarios.crear') || !canReadRoles) $('formCrearUsuario').classList.add('hidden');
    $('formCrearNegocio').classList.toggle('hidden', !(canReadBusinesses && canManageBusinesses));
    $('roleEditor').classList.toggle('hidden', !(currentPermissions.has('roles.gestionar') && canReadRoles));

    $('btnLogout').addEventListener('click', async () => {
        try { await api('/auth/logout', { method: 'POST' }); } catch (e) { /* se sale igual */ }
        window.location.href = 'index.html';
    });

    // Acciones de las tablas (delegación: nada de onclick inline con datos interpolados)
    document.addEventListener('click', e => {
        const b = e.target.closest('[data-action]');
        if (!b) return;
        const id = parseInt(b.dataset.id, 10);
        const acciones = {
            aprobar: () => aprob(id, 'APROBADO'),
            rechazar: () => aprob(id, 'RECHAZADO'),
            ban: () => toggleBan(id, b.dataset.activo === 'true'),
            borrar: () => deleteUser(id)
        };
        if (acciones[b.dataset.action]) acciones[b.dataset.action]();
    });
    document.addEventListener('change', e => {
        if (e.target.matches('select[data-rol-usuario]')) cambiarRol(parseInt(e.target.dataset.rolUsuario, 10), e.target.value);
    });

    document.querySelectorAll('[data-nav]').forEach(b => b.addEventListener('click', () => showSection(b.dataset.nav)));
    $('btnDashboardNegocio').addEventListener('click', () => showSection('directorio'));
    if ($('buscarDirectorio')) $('buscarDirectorio').addEventListener('input', renderDirectorio);
    if ($('filtroCategoria')) $('filtroCategoria').addEventListener('change', renderDirectorio);
    if ($('filtroMapaCategoria')) $('filtroMapaCategoria').addEventListener('change', pintarMarcadoresMapa);

    ['nLatitud', 'nLongitud'].forEach(id => $(id).addEventListener('change', moverMarcadorDesdeInputs));
    $('formCrearNegocio').addEventListener('submit', crearNegocio);
    $('formCrearUsuario').addEventListener('submit', crearUsuario);
    $('roleSelector').addEventListener('change', cargarRolSeleccionado);
    $('btnNewRole').addEventListener('click', prepararNuevoRol);
    $('btnSaveRole').addEventListener('click', guardarRol);
    $('btnDeleteRole').addEventListener('click', eliminarRol);
    $('btnNuevoUsuario').addEventListener('click', () => {
        const f = $('formCrearUsuario');
        f.classList.toggle('hidden');
        if (!f.classList.contains('hidden')) $('uNombre').focus();
    });

    const firstSection = ['dashboard', 'negocios', 'directorio', 'mapa', 'usuarios', 'auditoria']
        .find(section => allowedSections.has(section));
    if (firstSection) {
        showSection(firstSection);
        if (currentPermissions.has('negocios.gestionar')) actualizarContadorPendientes();
    } else {
        $('sectionTitle').textContent = 'Sin permisos asignados';
        $('sectionSubtitle').textContent = 'Contacta al administrador para solicitar acceso.';
        Object.keys(SECCIONES).forEach(section => $(`sec-${section}`).classList.add('hidden'));
    }
});

async function crearNegocio(e) {
    e.preventDefault();
    const form = e.target;
    const btn = form.querySelector('[type="submit"]');
    const lat = parseFloat($('nLatitud').value);
    const lng = parseFloat($('nLongitud').value);
    if (!esCoordValida(lat, lng)) {
        showAlert('Haz clic en el mapa para marcar la ubicación del negocio.', true);
        return;
    }
    const body = {
        nombre: $('nNombre').value.trim(),
        categoria: $('nCategoria').value.trim(),
        telefono: $('nTelefono').value.trim(),
        direccion: $('nDireccion').value.trim(),
        ciudad: $('nCiudad').value.trim(),
        horario: $('nHorario').value.trim(),
        descripcion: $('nDescripcion').value.trim(),
        usuario_id: parseInt($('nDueno').value, 10) || 0,
        latitud: String(lat),
        longitud: String(lng)
    };
    if (btn) btn.disabled = true;
    try {
        const res = await api('/admin/negocios', { method: 'POST', body: JSON.stringify(body) });
        console.log('crear negocio →', res);
        if (!res || !res.mensaje) throw new Error('El servidor no confirmó que el negocio se guardó. Revisa la pestaña Network (F12).');
        showAlert(res.mensaje);
        form.reset();
        if (marcadorFormulario) { mapaFormulario.removeLayer(marcadorFormulario); marcadorFormulario = null; }
        await cargarDirectorio();
    } catch (error) {
        showAlert(msgError(error), true);
    } finally {
        if (btn) btn.disabled = false;
    }
}

// ---------- navegación ----------
function showSection(id) {
    if (!SECCIONES[id] || !allowedSections.has(id)) return;
    Object.keys(SECCIONES).forEach(s => $(`sec-${s}`).classList.toggle('hidden', s !== id));
    document.querySelectorAll('[data-nav]').forEach(b => b.classList.toggle('active', b.dataset.nav === id));
    $('sectionTitle').textContent = SECCIONES[id][0];
    if ($('sectionSubtitle')) $('sectionSubtitle').textContent = SECCIONES[id][1];

    if (id === 'negocios') cargarNegociosPendientes();
    if (id === 'dashboard') cargarDashboard();
    if (id === 'directorio') { cargarDirectorio(); cargarDuenos(); setTimeout(initMapaFormulario, 150); }
    if (id === 'mapa') setTimeout(initMapaPrincipal, 150);
    if (id === 'usuarios') cargarUsuarios();
    if (id === 'auditoria') cargarAuditoria();
}

async function cargarDashboard() {
    const categoriesEl = $('resumenCategorias');
    const activityEl = $('resumenActividad');
    if (categoriesEl) categoriesEl.innerHTML = '<p class="small muted">Cargando estadísticas…</p>';
    if (activityEl) activityEl.innerHTML = '<p class="small muted">Cargando actividad…</p>';

    try {
        const [stats, negocios, pendientes, auditoria] = await Promise.all([
            api('/admin/stats'),
            currentPermissions.has('negocios.leer') ? api('/admin/negocios') : Promise.resolve([]),
            currentPermissions.has('negocios.gestionar') ? api('/admin/negocios/pendientes') : Promise.resolve([]),
            currentPermissions.has('auditoria.leer') ? api('/admin/auditoria') : Promise.resolve([])
        ]);
        const listaNegocios = asArray(negocios);
        const listaPendientes = asArray(pendientes);
        const categorias = listaNegocios.reduce((counts, negocio) => {
            const nombre = String(negocio.categoria || '').trim() || 'Sin categoría';
            counts.set(nombre, (counts.get(nombre) || 0) + 1);
            return counts;
        }, new Map());
        const categoriasOrdenadas = [...categorias.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], 'es'));
        const formato = new Intl.NumberFormat('es-MX');

        $('statUsuarios').textContent = formato.format(Number(stats.usuarios) || 0);
        $('statNegocios').textContent = currentPermissions.has('negocios.leer') ? formato.format(listaNegocios.length) : '—';
        $('statPendientes').textContent = currentPermissions.has('negocios.gestionar') ? formato.format(listaPendientes.length) : '—';
        $('statCategorias').textContent = formato.format(categorias.size);

        if (categoriesEl && currentPermissions.has('negocios.leer')) {
            if (!categoriasOrdenadas.length) {
                categoriesEl.innerHTML = '<p class="small muted">Aún no hay negocios aprobados.</p>';
            } else {
                const max = categoriasOrdenadas[0][1];
                categoriesEl.innerHTML = categoriasOrdenadas.map(([nombre, cantidad]) => `
                    <div class="category-row">
                        <span>${esc(nombre)}</span><strong>${formato.format(cantidad)}</strong>
                        <div class="category-track"><span class="category-fill" style="--c:${colorCategoria(nombre === 'Sin categoría' ? '' : nombre)};width:${Math.max(4, cantidad / max * 100)}%"></span></div>
                    </div>`).join('');
            }
        } else if (categoriesEl) {
            categoriesEl.innerHTML = '<p class="small muted">No tienes permiso para consultar negocios.</p>';
        }

        if (activityEl && currentPermissions.has('auditoria.leer')) {
            const eventos = asArray(auditoria).slice(0, 5);
            activityEl.innerHTML = eventos.length ? eventos.map(evento => `
                <div class="border-b pb-3 last:border-0" style="border-color:var(--line)">
                    <div class="text-sm font-semibold">${esc(evento.accion || 'Movimiento registrado')}</div>
                    <div class="small muted mt-1">${esc(evento.correo || 'Usuario eliminado')} · ${esc(evento.fecha || '')}</div>
                </div>`).join('') : '<p class="small muted">Aún no hay movimientos registrados.</p>';
        } else if (activityEl) {
            activityEl.innerHTML = '<p class="small muted">No tienes permiso para consultar auditoría.</p>';
        }
    } catch (error) {
        if (categoriesEl) categoriesEl.innerHTML = `<p class="small text-error">${esc(msgError(error))}</p>`;
        if (activityEl) activityEl.innerHTML = '<p class="small muted">No se pudo cargar la actividad.</p>';
        ['statUsuarios', 'statNegocios', 'statPendientes', 'statCategorias'].forEach(id => {
            if ($(id)) $(id).textContent = '—';
        });
    }
}

// ---------- auditoría ----------
async function cargarAuditoria() {
    const tb = $('tabla-auditoria');
    tb.innerHTML = filaMensaje(4, 'Cargando…');
    try {
        const data = asArray(await api('/admin/auditoria'));
        tb.innerHTML = data.length ? data.map(d => `
            <tr>
                <td class="td nowrap">${esc(d.fecha)}</td>
                <td class="td strong">${d.correo ? esc(d.correo) : '<span class="muted">Usuario eliminado</span>'}</td>
                <td class="td mono muted">${esc(d.ip)}</td>
                <td class="td">${esc(d.accion)}</td>
            </tr>`).join('') : filaMensaje(4, 'Todavía no hay movimientos registrados');
    } catch (e) {
        tb.innerHTML = filaMensaje(4, msgError(e), 'tabla-vacia text-error');
    }
}

// ---------- usuarios ----------
async function cargarUsuarios() {
    const tb = $('tabla-usuarios');
    tb.innerHTML = filaMensaje(4, 'Cargando…');
    try {
        const canManageUsers = currentPermissions.has('usuarios.gestionar');
        const canManageRoles = currentPermissions.has('roles.gestionar');
        const canReadRoles = currentPermissions.has('roles.leer');
        if (canReadRoles && rolesCache.length === 0) rolesCache = asArray(await api('/admin/roles'));
        if (currentPermissions.has('usuarios.crear') && canReadRoles) pintarSelectRoles();
        if (currentPermissions.has('roles.gestionar') && canReadRoles) await cargarEditorRoles();
        const data = asArray(await api('/admin/usuarios'));
        tb.innerHTML = data.length ? data.map(u => {
            const opts = rolesCache.map(r => `<option value="${esc(r.id)}" ${u.rol === r.nombre ? 'selected' : ''}>${esc(r.nombre)}</option>`).join('');
            const badge = u.activo ? '<span class="badge badge-ok">Activo</span>' : '<span class="badge badge-bad">Suspendido</span>';
            const rol = canManageRoles && canReadRoles
                ? `<select data-rol-usuario="${esc(u.id)}" class="input input-sm">${opts}</select>`
                : esc(u.rol);
            const actions = canManageUsers ? `
                <button data-action="ban" data-id="${esc(u.id)}" data-activo="${u.activo ? 'true' : 'false'}" class="btn btn-warn">${u.activo ? 'Suspender' : 'Reactivar'}</button>
                <button data-action="borrar" data-id="${esc(u.id)}" class="btn btn-danger">Borrar</button>` : '—';
            return `
            <tr>
                <td class="td"><div class="strong">${esc(u.nombre)}</div><div class="muted small">${esc(u.correo)}</div></td>
                <td class="td">${badge}</td>
                <td class="td">${rol}</td>
                <td class="td nowrap">${actions}</td>
            </tr>`;
        }).join('') : filaMensaje(4, 'No hay usuarios registrados');
    } catch (e) {
        tb.innerHTML = filaMensaje(4, msgError(e), 'tabla-vacia text-error');
    }
}

function pintarSelectRoles() {
    const sel = $('uRol');
    if (!sel) return;
    const actual = sel.value;
    const availableRoles = currentPermissions.has('roles.gestionar')
        ? rolesCache
        : rolesCache.filter(role => asArray(role.permisos).length === 0);
    sel.innerHTML = availableRoles.map(r => `<option value="${esc(r.id)}">${esc(r.nombre)}</option>`).join('');
    // Por defecto, el rol más básico si existe
    const basico = availableRoles.find(r => r.nombre === 'Usuario Regular');
    sel.value = availableRoles.some(role => String(role.id) === actual)
        ? actual
        : (basico ? String(basico.id) : '');
}

async function cargarEditorRoles(preferredRoleID = '') {
    const [roles, permisos] = await Promise.all([
        api('/admin/roles'),
        api('/admin/roles/permisos')
    ]);
    rolesCache = asArray(roles);
    permissionsCatalog = asArray(permisos);
    const selector = $('roleSelector');
    const selected = preferredRoleID || selector.value;
    selector.innerHTML = rolesCache.map(role =>
        `<option value="${esc(role.id)}">${esc(role.nombre)}</option>`).join('');
    if (rolesCache.some(role => String(role.id) === selected)) selector.value = selected;
    else selector.value = rolesCache.length ? String(rolesCache[0].id) : '';
    if (selector.value) cargarRolSeleccionado();
    else prepararNuevoRol();
}

function cargarRolSeleccionado() {
    const role = rolesCache.find(item => String(item.id) === $('roleSelector').value);
    if (!role) {
        prepararNuevoRol();
        return;
    }
    const isSystemRole = role.nombre === 'Administrador' || role.nombre === 'Usuario Regular';
    $('roleName').value = role.nombre;
    $('roleName').disabled = isSystemRole;
    $('roleDescription').value = role.descripcion || '';
    pintarCasillasPermisos(role.permisos, role.nombre === 'Administrador');
    $('btnDeleteRole').disabled = isSystemRole;
}

function pintarCasillasPermisos(selectedCodes, disabled) {
    const selected = new Set(asArray(selectedCodes));
    $('rolePermissionList').innerHTML = permissionsCatalog.map(permission => `
        <label class="flex items-start gap-2 rounded-lg border p-3 small" style="border-color:var(--line)">
          <input type="checkbox" data-role-permission="${esc(permission.codigo)}" ${selected.has(permission.codigo) ? 'checked' : ''} ${disabled ? 'disabled' : ''}>
          <span><strong>${esc(permission.nombre)}</strong><br><span class="muted">${esc(permission.descripcion)}</span></span>
        </label>`).join('');
}

function prepararNuevoRol() {
    $('roleSelector').value = '';
    $('roleName').value = '';
    $('roleName').disabled = false;
    $('roleDescription').value = '';
    $('btnDeleteRole').disabled = true;
    pintarCasillasPermisos([], false);
    $('roleName').focus();
}

async function guardarRol() {
    const name = $('roleName').value.trim();
    if (!name) {
        showAlert('Escribe el nombre del rol.', true);
        return;
    }
    const roleID = parseInt($('roleSelector').value, 10) || 0;
    const body = {
        nombre: name,
        descripcion: $('roleDescription').value.trim(),
        permisos: [...document.querySelectorAll('[data-role-permission]:checked')]
            .map(input => input.dataset.rolePermission)
    };
    const button = $('btnSaveRole');
    button.disabled = true;
    try {
        let selectedRoleID = String(roleID);
        if (roleID) {
            body.id = roleID;
            await api('/admin/roles/actualizar', { method: 'PUT', body: JSON.stringify(body) });
            showAlert('Rol y permisos actualizados');
        } else {
            const result = await api('/admin/roles/crear', { method: 'POST', body: JSON.stringify(body) });
            if (!result || !result.id) throw new Error('El servidor no confirmó que el rol se guardó.');
            selectedRoleID = String(result.id);
            showAlert('Rol creado');
        }
        await cargarEditorRoles(selectedRoleID);
        await cargarUsuarios();
    } catch (error) {
        showAlert(msgError(error), true);
    } finally {
        button.disabled = false;
    }
}

async function eliminarRol() {
    const roleID = parseInt($('roleSelector').value, 10) || 0;
    const role = rolesCache.find(item => item.id === roleID);
    if (!role || role.nombre === 'Administrador' || role.nombre === 'Usuario Regular') return;
    if (!confirm(`¿Eliminar el rol "${role.nombre}"? No se puede eliminar si todavía está asignado a usuarios.`)) return;
    try {
        await api('/admin/roles/eliminar', {
            method: 'DELETE',
            body: JSON.stringify({ rol_id: roleID })
        });
        showAlert('Rol eliminado');
        rolesCache = [];
        await cargarEditorRoles();
        await cargarUsuarios();
    } catch (error) {
        showAlert(msgError(error), true);
    }
}

async function crearUsuario(e) {
    e.preventDefault();
    const form = e.target;
    const btn = form.querySelector('[type="submit"]');
    const body = {
        nombre: $('uNombre').value.trim(),
        apellidos: $('uApellidos').value.trim(),
        correo: $('uCorreo').value.trim(),
        telefono: $('uTelefono').value.trim(),
        password: $('uPassword').value,
        rol_id: parseInt($('uRol').value, 10) || 0
    };
    if (body.password.length < 8) { showAlert('La contraseña debe tener al menos 8 caracteres.', true); return; }
    if (btn) btn.disabled = true;
    try {
        const res = await api('/admin/usuarios/crear', { method: 'POST', body: JSON.stringify(body) });
        console.log('crear usuario →', res);
        if (!res || !res.id) throw new Error('El servidor no confirmó que el usuario se guardó. Revisa la pestaña Network (F12).');
        showAlert(`Usuario creado (id ${res.id})`);
        form.reset();
        pintarSelectRoles();
        form.classList.add('hidden');
        cargarUsuarios();
    } catch (err) {
        showAlert(msgError(err), true);
    } finally {
        if (btn) btn.disabled = false;
    }
}

// Lista de posibles dueños para el formulario de negocios
async function cargarDuenos() {
    const sel = $('nDueno');
    if (!sel) return;
    try {
        const us = asArray(await api('/admin/usuarios'));
        const actual = sel.value;
        sel.innerHTML = '<option value="">Sin dueño asignado</option>' +
            us.filter(u => u.activo).map(u => `<option value="${esc(u.id)}">${esc(u.nombre)} · ${esc(u.correo)}</option>`).join('');
        sel.value = actual;
    } catch (e) { /* no crítico: se puede registrar sin dueño */ }
}

async function cambiarRol(uId, rId) {
    try {
        await api('/admin/usuarios/rol', { method: 'PUT', body: JSON.stringify({ UsuarioID: uId, RolID: parseInt(rId, 10) }) });
        showAlert('Rol actualizado');
    } catch (e) {
        showAlert(msgError(e), true);
        cargarUsuarios(); // deja el select como estaba realmente en la BD
    }
}
async function toggleBan(id, estabaActivo) {
    if (estabaActivo && !confirm('¿Suspender esta cuenta? No podrá iniciar sesión.')) return;
    try {
        await api('/admin/usuarios/ban', { method: 'PUT', body: JSON.stringify({ usuario_id: id }) });
        showAlert(estabaActivo ? 'Cuenta suspendida' : 'Cuenta reactivada');
        cargarUsuarios();
    } catch (e) { showAlert(msgError(e), true); }
}
async function deleteUser(id) {
    if (!confirm('¿Borrar permanentemente a este usuario? Esta acción no se puede deshacer.')) return;
    try {
        await api('/admin/usuarios/delete', { method: 'DELETE', body: JSON.stringify({ usuario_id: id }) });
        showAlert('Usuario eliminado');
        cargarUsuarios();
    } catch (e) { showAlert(msgError(e), true); }
}

// ---------- negocios pendientes ----------
async function cargarNegociosPendientes() {
    const tb = $('tabla-negocios');
    tb.innerHTML = filaMensaje(5, 'Cargando…');
    try {
        const data = asArray(await api('/admin/negocios/pendientes'));
        pintarContadorPendientes(data.length);
        tb.innerHTML = data.length ? data.map(n => `
            <tr>
                <td class="td muted">#${esc(n.id)}</td>
                <td class="td"><div class="strong">${esc(n.nombre)}</div>${n.direccion ? `<div class="muted small">${esc(n.direccion)}</div>` : ''}</td>
                <td class="td">${n.categoria ? `<span class="chip" style="--c:${colorCategoria(n.categoria)}">${esc(n.categoria)}</span>` : '—'}</td>
                <td class="td">${esc(n.telefono) || '—'}</td>
                <td class="td nowrap">
                    <button data-action="aprobar" data-id="${esc(n.id)}" class="btn btn-ok">Aprobar</button>
                    <button data-action="rechazar" data-id="${esc(n.id)}" class="btn btn-danger">Rechazar</button>
                </td>
            </tr>`).join('') : filaMensaje(5, 'No hay negocios pendientes. ¡Todo al día!');
    } catch (e) {
        tb.innerHTML = filaMensaje(5, msgError(e), 'tabla-vacia text-error');
    }
}
async function aprob(id, acc) {
    try {
        await api('/admin/negocios/aprobar', { method: 'PUT', body: JSON.stringify({ negocio_id: id, accion: acc }) });
        showAlert(acc === 'APROBADO' ? 'Negocio aprobado' : 'Negocio rechazado');
        cargarNegociosPendientes();
    } catch (e) { showAlert(msgError(e), true); }
}
function pintarContadorPendientes(n) {
    const b = $('badgePendientes');
    if (!b) return;
    b.textContent = n;
    b.classList.toggle('hidden', n === 0);
}
async function actualizarContadorPendientes() {
    try { pintarContadorPendientes(asArray(await api('/admin/negocios/pendientes')).length); } catch (e) { /* no crítico */ }
}

// ---------- directorio ----------
async function cargarDirectorio() {
    const tb = $('tabla-directorio');
    tb.innerHTML = filaMensaje(3, 'Cargando…');
    try {
        directorioCache = asArray(await api('/admin/negocios'));
        const sel = $('filtroCategoria');
        if (sel) {
            const actual = sel.value;
            const cats = [...new Set(directorioCache.map(n => n.categoria).filter(Boolean))].sort();
            sel.innerHTML = '<option value="">Todas las categorías</option>' + cats.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
            if (cats.includes(actual)) sel.value = actual;
        }
        renderDirectorio();
    } catch (e) {
        tb.innerHTML = filaMensaje(3, msgError(e), 'tabla-vacia text-error');
    }
}
function renderDirectorio() {
    const q = ($('buscarDirectorio') ? $('buscarDirectorio').value : '').trim().toLowerCase();
    const cat = $('filtroCategoria') ? $('filtroCategoria').value : '';
    const lista = directorioCache.filter(n =>
        (!cat || n.categoria === cat) &&
        (!q || `${n.nombre} ${n.categoria} ${n.telefono}`.toLowerCase().includes(q)));
    if ($('contadorDirectorio')) $('contadorDirectorio').textContent = `${lista.length} de ${directorioCache.length}`;
    $('tabla-directorio').innerHTML = lista.length ? lista.map(n => `
        <tr>
            <td class="td strong">${esc(n.nombre)}</td>
            <td class="td"><span class="chip" style="--c:${colorCategoria(n.categoria)}">${esc(n.categoria) || 'Sin categoría'}</span></td>
            <td class="td">${esc(n.telefono) || '—'}</td>
        </tr>`).join('') : filaMensaje(3, directorioCache.length ? 'Sin resultados para ese filtro' : 'Aún no hay negocios aprobados');
}

// ---------- mapa principal ----------
let mapaPrincipal;
let capaMarcadores;
let negociosMapaCache = [];

function iconoPin(color) {
    return L.divIcon({
        className: 'pin-wrap',
        html: `<span class="pin" style="--c:${color}"></span>`,
        iconSize: [28, 36], iconAnchor: [14, 34], popupAnchor: [0, -30]
    });
}

async function initMapaPrincipal() {
    if (!mapaPrincipal) {
        mapaPrincipal = L.map('mapaCanvas').setView(MAPA_CENTRO, 13);
        L.tileLayer(TILE_URL, { maxZoom: 19, attribution: TILE_ATTR }).addTo(mapaPrincipal);
        capaMarcadores = L.layerGroup().addTo(mapaPrincipal);
    }
    mapaPrincipal.invalidateSize();
    try {
        negociosMapaCache = asArray(await api('/admin/negocios'));
        const sel = $('filtroMapaCategoria');
        if (sel) {
            const actual = sel.value;
            const categorias = [...new Set(negociosMapaCache.map(n => String(n.categoria || '').trim() || 'Sin categoría'))]
                .sort((a, b) => a.localeCompare(b, 'es'));
            sel.innerHTML = '<option value="">Todas las categorías</option>' +
                categorias.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join('');
            if (categorias.includes(actual)) sel.value = actual;
        }
        pintarMarcadoresMapa();
    } catch (e) {
        showAlert(msgError(e), true);
    }
}

function pintarMarcadoresMapa() {
    if (!mapaPrincipal || !capaMarcadores) return;
    capaMarcadores.clearLayers();
    const categoriaSeleccionada = $('filtroMapaCategoria') ? $('filtroMapaCategoria').value : '';
    const filtrados = negociosMapaCache.filter(n => {
        const categoria = String(n.categoria || '').trim() || 'Sin categoría';
        return !categoriaSeleccionada || categoria === categoriaSeleccionada;
    });
    const puntos = [];
    let sinUbicacion = 0;

    filtrados.forEach(n => {
        const lat = parseFloat(n.latitud), lng = parseFloat(n.longitud);
        if (!esCoordValida(lat, lng)) { sinUbicacion++; return; }
        const categoria = String(n.categoria || '').trim() || 'Sin categoría';
        const tel = n.telefono ? `<br><a href="tel:${esc(n.telefono)}">${esc(n.telefono)}</a>` : '';
        L.marker([lat, lng], { icon: iconoPin(colorCategoria(categoria === 'Sin categoría' ? '' : categoria)) })
            .bindPopup(`<b>${esc(n.nombre)}</b><br>${esc(categoria)}${tel}`)
            .addTo(capaMarcadores);
        puntos.push([lat, lng]);
    });

    if (puntos.length) mapaPrincipal.fitBounds(puntos, { padding: [40, 40], maxZoom: 16 });
    if ($('infoMapa')) {
        $('infoMapa').textContent = `${puntos.length} negocio${puntos.length === 1 ? '' : 's'} en el mapa` +
            (sinUbicacion ? ` · ${sinUbicacion} sin ubicación válida` : '');
    }
    if ($('leyendaMapa')) {
        const categorias = [...new Set(filtrados.map(n => String(n.categoria || '').trim() || 'Sin categoría'))].sort((a, b) => a.localeCompare(b, 'es'));
        $('leyendaMapa').innerHTML = categorias.map(c =>
            `<span class="chip" style="--c:${colorCategoria(c === 'Sin categoría' ? '' : c)}">${esc(c)}</span>`).join('');
    }
}

// ---------- mapa del formulario ----------
let mapaFormulario;
let marcadorFormulario = null;

function colocarMarcadorFormulario(latlng) {
    if (marcadorFormulario) marcadorFormulario.setLatLng(latlng);
    else marcadorFormulario = L.marker(latlng).addTo(mapaFormulario);
}
function moverMarcadorDesdeInputs() {
    if (!mapaFormulario) return;
    const lat = parseFloat($('nLatitud').value), lng = parseFloat($('nLongitud').value);
    if (esCoordValida(lat, lng)) {
        colocarMarcadorFormulario([lat, lng]);
        mapaFormulario.setView([lat, lng], Math.max(mapaFormulario.getZoom(), 15));
    }
}
function initMapaFormulario() {
    if (!mapaFormulario) {
        mapaFormulario = L.map('mapaForm').setView(MAPA_CENTRO, 13);
        L.tileLayer(TILE_URL, { maxZoom: 19, attribution: TILE_ATTR }).addTo(mapaFormulario);
        mapaFormulario.on('click', e => {
            $('nLatitud').value = e.latlng.lat.toFixed(6);
            $('nLongitud').value = e.latlng.lng.toFixed(6);
            colocarMarcadorFormulario(e.latlng);
        });
    }
    setTimeout(() => mapaFormulario.invalidateSize(), 200);
}
