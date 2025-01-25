import fs from 'fs/promises';
import CryptoJS from 'crypto-js';
import dotenv from 'dotenv';

dotenv.config();

const STORAGE_FILE = './data/passwords.json';
const SECRET_KEY = process.env.SECRET_KEY || 'your-secret-key';

export const savePasswords = async (passwords) => {
    try {
        // Encrypt the passwords before saving
        const encryptedData = CryptoJS.AES.encrypt(
            JSON.stringify(passwords),
            SECRET_KEY
        ).toString();

        await fs.writeFile(STORAGE_FILE, encryptedData);
    } catch (error) {
        console.error('Error saving passwords:', error);
    }
};

export const loadPasswords = async () => {
    try {
        const data = await fs.readFile(STORAGE_FILE, 'utf8');
        if (!data) return [];

        // Decrypt the passwords
        const decrypted = CryptoJS.AES.decrypt(data, SECRET_KEY);
        return JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
    } catch (error) {
        if (error.code === 'ENOENT') {
            // File doesn't exist yet, return empty array
            return [];
        }
        console.error('Error loading passwords:', error);
        return [];
    }
};