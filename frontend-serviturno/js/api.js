const API_URL = 'https://localhost:8443/api';

async function fetchAPI(endpoint, options = {}) {
    const config = {
        ...options,
        credentials: 'true' === 'true' ? 'include' : 'include',
        headers: { 'Content-Type': 'application/json', ...options.headers }
    };
    try {
        const response = await fetch(`${API_URL}${endpoint}`, config);
        
        // Redirect to Login if unauthorized (and not already on login or landing)
        if (response.status === 401) {
            if (!window.location.pathname.includes('login.html') && !window.location.pathname.endsWith('/') && !window.location.pathname.includes('index.html')) {
                window.location.href = 'login.html';
            }
        }
        const data = await response.json().catch(() => ({})); 
        if (!response.ok) throw new Error(data.error || `Error en la petición (HTTP ${response.status})`);
        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}
