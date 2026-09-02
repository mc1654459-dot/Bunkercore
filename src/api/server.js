import express from 'express';
import path from 'path';
import { verifyIdentity } from '../core/auth/index.js';
import { encryptData, decryptData } from '../core/crypto/index.js';
import { recordEvent } from '../core/ledger/index.js';
import { validateTenant } from '../core/tenants/index.js';
import { db } from '../core/db/index.js';
// Importamos el guardia desde la raíz
import { checkAuthStatus } from '../../check_auth.js';
import { router as apiRouter } from './routes.js';

export const bunkercore = {
    init: () => {
        console.log("Bunkercore: Sistema iniciado y en modo Zero-Trust.");
    },

    processData: async (inputData, tenantId, userSignature) => {
        // --- BLINDAJE BIOMÉTRICO ---
        if (!checkAuthStatus()) {
            throw new Error("Acceso denegado: Se requiere autenticación biométrica.");
        }

        validateTenant(tenantId);
        if (!(await verifyIdentity(userSignature))) throw new Error("Acceso denegado: Firma FIDO2 inválida.");
        
        const securePayload = await encryptData(inputData, tenantId);
        const event = await recordEvent(tenantId, "DATA_ENCRYPTION", "Procesado y cifrado.");
        await db.saveData(tenantId, securePayload, event.fingerprint);
        
        return { status: "SECURED_AND_SAVED", data: securePayload, fingerprint: event.fingerprint };
    },
    
    retrieveData: async (tenantId, userSignature) => {
        if (!checkAuthStatus()) {
            throw new Error("Acceso denegado: Se requiere autenticación biométrica.");
        }

        validateTenant(tenantId);
        if (!(await verifyIdentity(userSignature))) throw new Error("Acceso denegado: Firma FIDO2 inválida.");
        
        const secureBlob = await db.getData(tenantId);
        if (!secureBlob) throw new Error("No hay datos encontrados para este tenant.");
        
        const data = await decryptData(secureBlob);
        await recordEvent(tenantId, "DATA_RETRIEVAL", "Consulta exitosa.");
        
        return data;
    }
};

bunkercore.init();

// --- HTTP SERVER SETUP ---
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// API Routes mounted on both /api and root level for backwards compatibility
app.use('/api', apiRouter);
app.use('/', apiRouter);

// Static frontend serving
const publicDir = path.join(process.cwd(), 'public');
app.use(express.static(publicDir));

// SPA fallback to index.html for any unhandled page request
app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) {
        return next();
    }
    res.sendFile(path.join(publicDir, 'index.html'));
});

// Export Express app
export { app };

// Start Server binding to 0.0.0.0
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Bunkercore] Servidor activo en http://0.0.0.0:${PORT}`);
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.log(`[Bunkercore] Puerto ${PORT} en uso por el servidor principal.`);
    } else {
        console.error('[Bunkercore] Error del servidor:', err);
    }
});


