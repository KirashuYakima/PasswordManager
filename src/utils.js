export const generatePassword = (options = {
    length: 16,
    numbers: true,
    symbols: true,
    uppercase: true,
    lowercase: true
}) => {
    const numbers = "0123456789";
    const symbols = "!@#$%^&*_-+=";
    const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lowercase = "abcdefghijklmnopqrstuvwxyz";

    let chars = "";
    if (options.numbers) chars += numbers;
    if (options.symbols) chars += symbols;
    if (options.uppercase) chars += uppercase;
    if (options.lowercase) chars += lowercase;

    let password = "";
    for (let i = 0; i < options.length; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
};

export const checkPasswordStrength = (password) => {
    let score = 0;
    
    if (password.length >= 12) score += 2;
    else if (password.length >= 8) score += 1;
    
    if (/[0-9]/.test(password)) score += 1;
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    
    if (score < 2) return 'Weak';
    if (score < 4) return 'Medium';
    return 'Strong';
};