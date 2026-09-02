import { readFileSync, writeFileSync } from 'fs';

let inMemoryAuth = {
    authenticated: true, // Default to true in AI Studio dev environment for seamless access, controllable via API/UI
    user: 'admin-david',
    lastAuthTime: new Date().toISOString()
};

export function setAuthStatus(status, user = 'admin-david') {
    inMemoryAuth = {
        authenticated: !!status,
        user,
        lastAuthTime: new Date().toISOString()
    };
    try {
        writeFileSync('auth.json', JSON.stringify({
            auth_result: status ? "AUTH_RESULT_SUCCESS" : "AUTH_RESULT_FAILED",
            user: user,
            timestamp: inMemoryAuth.lastAuthTime
        }, null, 2));
    } catch {
        // Ignored if write fails
    }
}

export function getAuthInfo() {
    return { ...inMemoryAuth };
}

export function checkAuthStatus() {
    // 1. Check in-memory session first
    if (inMemoryAuth.authenticated) {
        return true;
    }

    try {
        // 2. Read auth.json if present
        const data = readFileSync('auth.json', 'utf8');
        const result = JSON.parse(data);
        
        // Validamos la respuesta del sensor
        if (result.auth_result === "AUTH_RESULT_SUCCESS") {
            console.log("✅ Acceso permitido: Huella válida detectada en auth.json.");
            inMemoryAuth.authenticated = true;
            return true;
        } else {
            console.log("❌ Acceso denegado: Firma incorrecta o falla de sensor.");
            return false;
        }
    } catch {
        return inMemoryAuth.authenticated;
    }
}

