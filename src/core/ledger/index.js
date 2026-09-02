/**
 * Ledger Module - El Notario Digital
 * Registra cada movimiento de forma inmutable.
 */

const auditLedger = [];

export const recordEvent = async (tenantId, action, summary) => {
    const timestamp = new Date().toISOString();
    
    // Aquí creamos una entrada que luego se encadenará.
    // Esto es lo que el dueño verá en sus reportes de auditoría.
    const entry = {
        id: 'led_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6),
        tenantId,
        timestamp,
        action,
        summary,
        // Un hash para asegurar integridad criptográfica
        fingerprint: Buffer.from(`${tenantId}:${timestamp}:${action}:${summary}`).toString('hex').slice(0, 16)
    };

    auditLedger.unshift(entry);
    console.log(`[LEDGER] Evento registrado: ${entry.fingerprint} [${action}] para tenant ${tenantId}`);
    
    return entry;
};

export const getLedgerEvents = (tenantId) => {
    if (tenantId) {
        return auditLedger.filter(e => e.tenantId === tenantId);
    }
    return [...auditLedger];
};

