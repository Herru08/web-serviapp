document.addEventListener('DOMContentLoaded', async () => {
    cargarMetricasPublicas();
    try {
        const res = await fetchAPI('/auth/me');
        if(res.rol === 'Administrador') window.location.href = 'dashboard.html';
    } catch(e) { }

    document.getElementById('formLogin')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
            const data = await fetchAPI('/auth/login', {
                method: 'POST', body: JSON.stringify({ correo: document.getElementById('lCorreo').value, password: document.getElementById('lPass').value })
            });
            if (data.rol === 'Administrador') window.location.href = 'dashboard.html';
            else showAlert('Acceso denegado: Solo admins', true);
        } catch (error) { showAlert(error.message, true); }
    });

    document.getElementById('formReg')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        try {
            await fetchAPI('/auth/register', {
                method: 'POST', body: JSON.stringify({ 
                    nombre: document.getElementById('rNombre').value, 
                    correo: document.getElementById('rCorreo').value, 
                    password: document.getElementById('rPass').value 
                })
            });
            showAlert('Cuenta creada. Ya puedes iniciar sesión.', false);
            switchTab('login');
        } catch (error) { showAlert(error.message, true); }
    });
});

async function cargarMetricasPublicas() {
    const format = value => Number.isInteger(value) ? new Intl.NumberFormat('es-MX').format(value) : '—';
    try {
        const stats = await fetchAPI('/public/stats');
        document.getElementById('metricUsers').textContent = format(stats.usuarios);
        document.getElementById('metricBusinesses').textContent = format(stats.negocios);
    } catch (error) {
        document.getElementById('metricUsers').textContent = '—';
        document.getElementById('metricBusinesses').textContent = '—';
    }
}

function switchTab(tab) {
    document.getElementById('formLogin').classList.toggle('hidden', tab !== 'login');
    document.getElementById('formReg').classList.toggle('hidden', tab !== 'register');
    document.getElementById('tabLogin').setAttribute('aria-selected', String(tab === 'login'));
    document.getElementById('tabReg').setAttribute('aria-selected', String(tab === 'register'));
}

function showAlert(msg, error) {
    const el = document.getElementById('alertMsg');
    el.textContent = msg;
    el.className = `mb-5 rounded-lg p-3 text-sm font-semibold ${error ? 'bg-red-50 text-red-700' : 'bg-emerald-50 text-emerald-800'}`;
    el.classList.remove('hidden');
    setTimeout(() => el.classList.add('hidden'), 4000);
}

function recuperar() {
    showAlert('Para recuperar el acceso, contacta al administrador. Por seguridad, la contraseña no se cambia solo con el correo.', true);
}
