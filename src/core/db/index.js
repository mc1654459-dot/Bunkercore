import postgres from 'postgres';
import 'dotenv/config';

// In-memory fallback storage when DATABASE_URL is not configured or offline
const inMemoryStore = {
    inventory_records: [],
    credentials: []
};

let sql = null;
let useMock = true;

if (process.env.DATABASE_URL) {
    try {
        sql = postgres(process.env.DATABASE_URL, { 
            ssl: 'require', 
            connect_timeout: 3,
            max: 5,
            idle_timeout: 10
        });
        useMock = false;
        console.log('[DB] PostgreSQL / Neon client initialized.');
    } catch (err) {
        console.warn('[DB] PostgreSQL init failed, using in-memory store:', err.message);
        useMock = true;
    }
} else {
    console.log('[DB] DATABASE_URL not provided. Active mode: In-Memory Zero-Trust Vault.');
}

/**
 * DB Module con aislamiento Multitenant (RLS ready) y compatibilidad Offline / Mock
 */
export const db = {
    isMock: () => useMock,

    /**
     * Guarda datos asegurando que el contexto del Tenant esté configurado.
     */
    saveData: async (tenantId, payload, fingerprint) => {
        if (!useMock && sql) {
            try {
                return await sql.begin(async sqlTx => {
                    await sqlTx`SELECT set_config('app.current_tenant_id', ${tenantId}, true)`;
                    return await sqlTx`
                        INSERT INTO inventory_records (tenant_id, secure_data, fingerprint)
                        VALUES (${tenantId}, ${payload}, ${fingerprint})
                        RETURNING id, created_at
                    `;
                });
            } catch (err) {
                console.warn('[DB] Postgres write error, falling back to memory store:', err.message);
            }
        }

        // In-memory fallback
        const record = {
            id: 'rec_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
            tenant_id: tenantId,
            secure_data: payload,
            fingerprint: fingerprint,
            created_at: new Date().toISOString()
        };
        inMemoryStore.inventory_records.unshift(record);
        return [record];
    },

    /**
     * Recupera el último dato filtrado automáticamente por RLS o por TenantId en memoria.
     */
    getData: async (tenantId) => {
        if (!useMock && sql) {
            try {
                return await sql.begin(async sqlTx => {
                    await sqlTx`SELECT set_config('app.current_tenant_id', ${tenantId}, true)`;
                    const result = await sqlTx`
                        SELECT secure_data FROM inventory_records 
                        ORDER BY created_at DESC LIMIT 1
                    `;
                    return result[0]?.secure_data;
                });
            } catch (err) {
                console.warn('[DB] Postgres read error, falling back to memory store:', err.message);
            }
        }

        const match = inMemoryStore.inventory_records.find(r => r.tenant_id === tenantId);
        return match ? match.secure_data : null;
    },

    /**
     * Recupera todos los registros para un Tenant o todos los tenants si tenantId no se pasa
     */
    getAllData: async (tenantId) => {
        if (!useMock && sql) {
            try {
                return await sql.begin(async sqlTx => {
                    if (tenantId) {
                        await sqlTx`SELECT set_config('app.current_tenant_id', ${tenantId}, true)`;
                        return await sqlTx`
                            SELECT id, tenant_id, secure_data, fingerprint, created_at 
                            FROM inventory_records 
                            ORDER BY created_at DESC
                        `;
                    } else {
                        return await sqlTx`
                            SELECT id, tenant_id, secure_data, fingerprint, created_at 
                            FROM inventory_records 
                            ORDER BY created_at DESC
                        `;
                    }
                });
            } catch (err) {
                console.warn('[DB] Postgres query error:', err.message);
            }
        }

        if (tenantId) {
            return inMemoryStore.inventory_records.filter(r => r.tenant_id === tenantId);
        }
        return [...inMemoryStore.inventory_records];
    },

    /**
     * Guarda credenciales FIDO2 / WebAuthn
     */
    saveCredential: async (credential) => {
        if (!useMock && sql) {
            try {
                await sql`
                    INSERT INTO credentials (id, public_key, counter)
                    VALUES (${credential.id}, ${credential.publicKey}, ${credential.counter})
                    ON CONFLICT (id) DO UPDATE SET counter = ${credential.counter}
                `;
                return true;
            } catch (err) {
                console.warn('[DB] Postgres credential save error:', err.message);
            }
        }

        const existingIdx = inMemoryStore.credentials.findIndex(c => c.id === credential.id);
        if (existingIdx >= 0) {
            inMemoryStore.credentials[existingIdx] = { ...inMemoryStore.credentials[existingIdx], ...credential };
        } else {
            inMemoryStore.credentials.push(credential);
        }
        return true;
    },

    /**
     * Obtiene credencial por ID
     */
    getCredential: async (id) => {
        if (!useMock && sql) {
            try {
                const res = await sql`SELECT id, public_key, counter FROM credentials WHERE id = ${id}`;
                if (res && res.length > 0) return res[0];
            } catch (err) {
                console.warn('[DB] Postgres credential query error:', err.message);
            }
        }
        return inMemoryStore.credentials.find(c => c.id === id) || null;
    },

    /**
     * Obtiene todas las credenciales
     */
    getCredentials: async () => {
        if (!useMock && sql) {
            try {
                const res = await sql`SELECT id, public_key, counter FROM credentials`;
                return res || [];
            } catch (err) {
                console.warn('[DB] Postgres credentials list error:', err.message);
            }
        }
        return [...inMemoryStore.credentials];
    }
};

export { sql };

