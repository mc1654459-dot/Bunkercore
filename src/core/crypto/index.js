import crypto from 'crypto';
import 'dotenv/config';

// La MASTER_KEY debe tener exactamente 32 bytes (256 bits) para AES-256.
// Se recomienda configurarla en el .env con 64 caracteres hexadecimales.
const DEFAULT_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

function getMasterKey() {
    const rawKey = process.env.MASTER_KEY || process.env.ENCRYPTION_KEY || DEFAULT_KEY;
    try {
        const buf = Buffer.from(rawKey, 'hex');
        if (buf.length === 32) {
            return buf;
        }
        // If not 32 bytes hex, create a SHA-256 hash to ensure 32 bytes
        return crypto.createHash('sha256').update(String(rawKey)).digest();
    } catch {
        return Buffer.from(DEFAULT_KEY, 'hex');
    }
}

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // Tamaño recomendado para GCM
const AUTH_TAG_LENGTH = 16;

/**
 * Cifra datos utilizando AES-256-GCM.
 * Retorna un string con el formato: iv:authTag:encryptedData
 */
export const encryptData = async (data) => {
    try {
        const iv = crypto.randomBytes(IV_LENGTH);
        const key = getMasterKey();
        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

        const textToEncrypt = typeof data === 'string' ? data : JSON.stringify(data);
        
        let encrypted = cipher.update(textToEncrypt, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag().toString('hex');

        // Formato seguro: iv:etiqueta:datos
        return `${iv.toString('hex')}:${authTag}:${encrypted}`;
    } catch (error) {
        console.error("[CRYPTO ENCRYPTION ERROR]:", error);
        throw new Error("Fallo al cifrar los datos.");
    }
};

/**
 * Descifra datos cifrados con AES-256-GCM.
 */
export const decryptData = async (secureBlob) => {
    try {
        const [ivHex, authTagHex, encryptedHex] = secureBlob.split(':');
        
        if (!ivHex || !authTagHex || !encryptedHex) {
            throw new Error("Formato de blob cifrado inválido.");
        }

        const key = getMasterKey();
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        const encryptedText = Buffer.from(encryptedHex, 'hex');

        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        // Intentar parsear si era un objeto JSON
        try {
            return JSON.parse(decrypted);
        } catch {
            return decrypted;
        }
    } catch (error) {
        console.error("[CRYPTO DECRYPTION ERROR]:", error);
        throw new Error("Fallo al descifrar: La llave es incorrecta o los datos fueron manipulados.");
    }
};
