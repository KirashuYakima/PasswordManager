import inquirer from 'inquirer';
import chalk from 'chalk';
import clipboardy from 'clipboardy';
import { savePasswords, loadPasswords } from './fileHandler.js';
import { generatePassword, checkPasswordStrength } from './utils.js';
import fs from 'fs/promises';

let passwords = [];
let categories = [];

// ASCII Header
const ASCII_HEADER = chalk.magenta(`
    ██████╗  █████╗ ███████╗███████╗██╗    ██╗██████╗  █████╗ ███████╗███████╗
    ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔══██╗██╔══██╗██╔════╝██╔════╝
    ██████╔╝███████║███████╗███████╗██║ █╗ ██║██████╔╝███████║███████╗███████╗
    ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██╔═══╝ ██╔══██║╚════██║╚════██║
    ██║     ██║  ██║███████║███████║╚███╔███╔╝██║     ██║  ██║███████║███████║
    ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝ ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
`);

// Loading animation frames
const frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

// Function to clear the screen and center output
const clearAndCenter = (text = '') => {
    console.clear();
    const lines = text.split('\n');
    const terminalWidth = process.stdout.columns;
    const terminalHeight = process.stdout.rows;
    const verticalPadding = Math.max(0, Math.floor((terminalHeight - lines.length) / 2));
    const horizontalPadding = Math.max(0, Math.floor((terminalWidth - Math.max(...lines.map(line => line.length))) / 2));

    console.log('\n'.repeat(verticalPadding)); // Add vertical padding
    lines.forEach(line => {
        console.log(' '.repeat(horizontalPadding) + line); // Add horizontal padding
    });
};

// Loading screen function
const showLoadingScreen = async () => {
    let i = 0;

    // Display initial loading screen
    const initialScreen = chalk.cyan(`
         ○   ○ 
        ═══════
    `);
    clearAndCenter(initialScreen);

    // Start loading animation
    const loadingInterval = setInterval(() => {
        const loadingText = chalk.cyan(`${frames[i]} Loading PasswPass...`);
        clearAndCenter(initialScreen + '\n\n' + loadingText);
        i = (i + 1) % frames.length;
    }, 80);

    // Simulate loading time
    await new Promise(resolve => setTimeout(resolve, 2000));
    clearInterval(loadingInterval);
    console.clear();

    // Display the main ASCII header
    clearAndCenter(ASCII_HEADER + '\n' + chalk.magenta('Version - 1.0.0 | Core - 0.9.5\n'));
};

// Password analysis and alerts class
class PasswordAnalyzer {
    constructor(passwords) {
        this.passwords = passwords;
    }

    analyzePasswords() {
        const alerts = [];
        
        // Check for duplicate sites
        const duplicateSites = this.findDuplicateSites();
        if (duplicateSites.length > 0) {
            duplicateSites.forEach(({site, count}) => {
                alerts.push({
                    type: 'warning',
                    message: `Found ${count} duplicate entries for site "${site}"`,
                    color: 'yellow'
                });
            });
        }

        // Check for duplicate passwords
        const duplicatePasswords = this.findDuplicatePasswords();
        if (duplicatePasswords.length > 0) {
            alerts.push({
                type: 'critical',
                message: `Found ${duplicatePasswords.length} passwords that are used multiple times`,
                color: 'red'
            });
        }

        // Check for weak passwords
        const weakPasswords = this.findWeakPasswords();
        if (weakPasswords.length > 0) {
            alerts.push({
                type: 'warning',
                message: `Detected ${weakPasswords.length} weak passwords`,
                color: 'yellow'
            });
        }

        // Check for missing information
        const incompletEntries = this.findIncompleteEntries();
        if (incompletEntries.length > 0) {
            alerts.push({
                type: 'warning',
                message: `Found ${incompletEntries.length} entries with missing information`,
                color: 'yellow'
            });
        }

        return alerts;
    }

    findDuplicateSites() {
        const siteCounts = {};
        this.passwords.forEach(p => {
            siteCounts[p.site.toLowerCase()] = (siteCounts[p.site.toLowerCase()] || 0) + 1;
        });

        return Object.entries(siteCounts)
            .filter(([_, count]) => count > 1)
            .map(([site, count]) => ({site, count}));
    }

    findDuplicatePasswords() {
        const passwordCounts = {};
        this.passwords.forEach(p => {
            passwordCounts[p.password] = (passwordCounts[p.password] || 0) + 1;
        });

        return Object.entries(passwordCounts)
            .filter(([_, count]) => count > 1)
            .map(([password]) => password);
    }

    findWeakPasswords() {
        return this.passwords.filter(p => {
            const password = p.password;
            return (
                password.length < 8 || // Too short
                !/[A-Z]/.test(password) || // No uppercase
                !/[a-z]/.test(password) || // No lowercase
                !/[0-9]/.test(password) || // No numbers
                !/[^A-Za-z0-9]/.test(password) // No special characters
            );
        });
    }

    findIncompleteEntries() {
        return this.passwords.filter(p => 
            !p.site?.trim() || !p.username?.trim() || !p.password?.trim()
        );
    }

    getDetailedAnalysis() {
        const analysis = {
            duplicateSites: this.findDuplicateSites(),
            duplicatePasswords: this.findDuplicatePasswords(),
            weakPasswords: this.findWeakPasswords(),
            incompleteEntries: this.findIncompleteEntries()
        };

        return analysis;
    }
}

const displayAlerts = async (passwords) => {
    console.clear();
    const analyzer = new PasswordAnalyzer(passwords);
    const alerts = analyzer.analyzePasswords();
    
    if (alerts.length > 0) {
        console.log(chalk.bold('\n🚨 Security Alerts:'));
        alerts.forEach(alert => {
            console.log(chalk[alert.color](`⚠ ${alert.message}`));
        });
        
        // If there are critical alerts, ask for acknowledgment
        if (alerts.some(alert => alert.type === 'critical')) {
            await inquirer.prompt([
                {
                    type: 'input',
                    name: 'acknowledge',
                    message: chalk.red('Press Enter to acknowledge these security risks...')
                }
            ]);
        }
    }
};

// Modified main menu to include loading screen
const mainMenu = async () => {
    await showLoadingScreen();

    await displayAlerts(passwords);

    // Display statistics for passwords saved
    console.log(chalk.green(`Passwords saved: ${passwords.length}`));

    const { action } = await inquirer.prompt([
        {
            type: 'list',
            name: 'action',
            message: chalk.magenta('passwpass@menu$→'),
            choices: [
                '⟨00⟩ → [View Alerts]',
                '⟨01⟩ → [Add Password]',
                '⟨02⟩ → [View Passwords]',
                '⟨03⟩ → [Export Backup]',
                '⟨04⟩ → [Password Check]',
                '⟨05⟩ → [Generate Password]',
                '⟨06⟩ → [Delete Password]',
                '⟨07⟩ → [Manage Categories]',
                '⟨08⟩ → [Exit]',
            ],
        },
    ]);

    const choice = action.split('→')[1].trim().replace('[', '').replace(']', '');

    switch (choice) {
        case 'View Alerts':
            await viewSecurityAnalysis();
            break;
        case 'Add Password':
            await addPassword();
            break;
        case 'View Passwords':
            await viewPasswords();
            break;
        case 'Export Backup':
            await exportBackup();
            break;
        case 'Password Check':
            await passwordCheck();
            break;
        case 'Generate Password':
            await generateAndSavePassword();
            break;
        case 'Delete Password':
            await deletePassword();
            break;
        case 'Manage Categories':
            await manageCategoriesMenu();
            break;
        case 'Exit':
            console.log(chalk.magenta('\nGoodbye!'));
            process.exit(0);
    }
};

const viewSecurityAnalysis = async () => {
    console.clear();
    console.log(chalk.cyan.bold(`
╔════════════════════════════════════════════════════╗
║           🔒 SECURITY ANALYSIS REPORT 🔒          ║
╚════════════════════════════════════════════════════╝
`));

    const analyzer = new PasswordAnalyzer(passwords);
    const analysis = analyzer.getDetailedAnalysis();

    // Display duplicate sites
    if (analysis.duplicateSites.length > 0) {
        console.log(chalk.yellow('\n📊 Duplicate Sites:'));
        analysis.duplicateSites.forEach(({site, count}) => {
            console.log(chalk.yellow(`  ⚠ "${site}" appears ${count} times`));
        });
    }

    // Display duplicate passwords
    if (analysis.duplicatePasswords.length > 0) {
        console.log(chalk.red('\n🔑 Duplicate Passwords:'));
        console.log(chalk.red(`  ⚠ ${analysis.duplicatePasswords.length} passwords are used multiple times`));
    }

    // Display weak passwords
    if (analysis.weakPasswords.length > 0) {
        console.log(chalk.yellow('\n💪 Weak Passwords:'));
        analysis.weakPasswords.forEach(entry => {
            console.log(chalk.yellow(`  ⚠ Weak password for site: ${entry.site}`));
        });
    }

    // Display incomplete entries
    if (analysis.incompleteEntries.length > 0) {
        console.log(chalk.yellow('\n❌ Incomplete Entries:'));
        analysis.incompleteEntries.forEach(entry => {
            console.log(chalk.yellow(`  ⚠ Incomplete entry for site: ${entry.site || 'Unknown Site'}`));
        });
    }

    if (Object.values(analysis).every(arr => arr.length === 0)) {
        console.log(chalk.green('\n✅ No security issues found!'));
    }

    await pauseMenu();
};

// Load categories from file
const loadCategories = async () => {
    try {
        const data = await fs.readFile('./data/categories.json', 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return [];
    }
};

// Save categories to file
const saveCategories = async (categories) => {
    try {
        await fs.writeFile('./data/categories.json', JSON.stringify(categories, null, 2));
    } catch (error) {
        console.log(chalk.red('Error saving categories:', error.message));
    }
};

// Category management menu
const manageCategoriesMenu = async () => {
    console.clear();
    console.log(chalk.cyan.bold(`
╔════════════════════════════════════════════════════╗
║            📁  CATEGORY MANAGEMENT  📁            ║
╚════════════════════════════════════════════════════╝
`));

    const { action } = await inquirer.prompt([
        {
            type: 'list',
            name: 'action',
            message: chalk.magenta('Select an action:'),
            choices: [
                '➕ Add Category',
                '✏️  Edit Category',
                '❌ Remove Category',
                '📋 View Categories',
                '↩️  Back'
            ]
        }
    ]);

    switch (action) {
        case '➕ Add Category':
            await addCategory();
            break;
        case '✏️  Edit Category':
            await editCategory();
            break;
        case '❌ Remove Category':
            await removeCategory();
            break;
        case '📋 View Categories':
            await viewCategories();
            break;
        case '↩️  Back':
            return;
    }

    await manageCategoriesMenu();
};

const addCategory = async () => {
    const { categoryName } = await inquirer.prompt([
        {
            type: 'input',
            name: 'categoryName',
            message: chalk.magenta('Enter new category name:'),
            validate: (input) => {
                if (!input.trim()) return 'Category name cannot be empty';
                if (categories.includes(input.trim())) return 'Category already exists';
                return true;
            }
        }
    ]);

    categories.push(categoryName.trim());
    await saveCategories(categories);
    console.log(chalk.green('\n✅ Category added successfully!'));
    await pauseMenu();
};

const editCategory = async () => {
    if (categories.length === 0) {
        console.log(chalk.yellow('\nNo categories exist yet.'));
        await pauseMenu();
        return;
    }

    const { categoryIndex } = await inquirer.prompt([
        {
            type: 'list',
            name: 'categoryIndex',
            message: chalk.magenta('Select category to edit:'),
            choices: categories.map((cat, idx) => ({
                name: `📁 ${cat}`,
                value: idx
            }))
        }
    ]);

    const { newName } = await inquirer.prompt([
        {
            type: 'input',
            name: 'newName',
            message: chalk.magenta('Enter new name:'),
            default: categories[categoryIndex],
            validate: (input) => {
                if (!input.trim()) return 'Category name cannot be empty';
                if (categories.includes(input.trim()) && input.trim() !== categories[categoryIndex]) {
                    return 'Category already exists';
                }
                return true;
            }
        }
    ]);

    // Update category name in passwords array
    passwords.forEach(pwd => {
        if (pwd.category === categories[categoryIndex]) {
            pwd.category = newName.trim();
        }
    });

    // Update category name in categories array
    categories[categoryIndex] = newName.trim();

    await Promise.all([
        saveCategories(categories),
        savePasswords(passwords)
    ]);

    console.log(chalk.green('\n✅ Category updated successfully!'));
    await pauseMenu();
};

const removeCategory = async () => {
    if (categories.length === 0) {
        console.log(chalk.yellow('\nNo categories exist yet.'));
        await pauseMenu();
        return;
    }

    const { categoryIndex } = await inquirer.prompt([
        {
            type: 'list',
            name: 'categoryIndex',
            message: chalk.magenta('Select category to remove:'),
            choices: categories.map((cat, idx) => ({
                name: `📁 ${cat} (${passwords.filter(p => p.category === cat).length} passwords)`,
                value: idx
            }))
        }
    ]);

    const { confirm } = await inquirer.prompt([
        {
            type: 'confirm',
            name: 'confirm',
            message: chalk.red(`Are you sure you want to remove "${categories[categoryIndex]}"?`),
            default: false
        }
    ]);

    if (confirm) {
        const categoryName = categories[categoryIndex];
        // Remove category from passwords
        passwords.forEach(pwd => {
            if (pwd.category === categoryName) {
                delete pwd.category;
            }
        });

        // Remove category from categories array
        categories.splice(categoryIndex, 1);

        await Promise.all([
            saveCategories(categories),
            savePasswords(passwords)
        ]);

        console.log(chalk.green('\n✅ Category removed successfully!'));
    }
    await pauseMenu();
};

const viewCategories = async () => {
    console.clear();
    console.log(chalk.cyan.bold(`
╔════════════════════════════════════════════════════╗
║               📁  CATEGORIES  📁                  ║
╚════════════════════════════════════════════════════╝
`));

    if (categories.length === 0) {
        console.log(chalk.yellow('No categories exist yet.'));
    } else {
        categories.forEach((category, index) => {
            const passwordCount = passwords.filter(p => p.category === category).length;
            console.log(chalk.cyan(`⟨${String(index + 1).padStart(2, '0')}⟩ → ${category} (${passwordCount} passwords)`));
        });
    }

    await pauseMenu();
};

// Modify your addPassword function to include category selection
const selectCategory = async () => {
    const { wantCategory } = await inquirer.prompt([
        {
            type: 'confirm',
            name: 'wantCategory',
            message: chalk.magenta('Would you like to add a category?'),
            default: false
        }
    ]);

    if (!wantCategory) {
        return null;
    }

    const choices = [
        ...categories.map(cat => ({
            name: `📁 ${cat}`,
            value: cat
        })),
        new inquirer.Separator(),
        { name: '➕ Create New Category', value: 'NEW' }
    ];

    const { category } = await inquirer.prompt([
        {
            type: 'list',
            name: 'category',
            message: chalk.magenta('Select a category:'),
            choices
        }
    ]);

    if (category === 'NEW') {
        const { newCategory } = await inquirer.prompt([
            {
                type: 'input',
                name: 'newCategory',
                message: chalk.magenta('Enter new category name:'),
                validate: (input) => {
                    if (!input.trim()) return 'Category name cannot be empty';
                    if (categories.includes(input.trim())) return 'Category already exists';
                    return true;
                }
            }
        ]);
        
        categories.push(newCategory.trim());
        await saveCategories(categories);
        return newCategory.trim();
    }

    return category;
};

const addPassword = async () => {
    const { choice } = await inquirer.prompt([
        {
            type: 'list',
            name: 'choice',
            message: chalk.magenta('Would you like to add a manual password or generate one?'),
            choices: ['Manual Password', 'Generate Password'],
        },
    ]);

    if (choice === 'Generate Password') {
        await generateAndSavePassword();
        return;
    }

    const { site, username, password } = await inquirer.prompt([
        {
            type: 'input',
            name: 'site',
            message: chalk.magenta('Enter site:'),
        },
        {
            type: 'input',
            name: 'username',
            message: chalk.magenta('Enter username:'),
        },
        {
            type: 'password',
            name: 'password',
            message: chalk.magenta('Enter password:'),
        },
    ]);

    const category = await selectCategory();

    passwords.push({ site, username, password, category });
    await savePasswords(passwords);

    console.log(chalk.green('\nPassword added successfully!'));
    await pauseMenu();
};

const generateAndSavePassword = async () => {
    const { length, includeNumbers, includeSymbols, includeUppercase, includeLowercase } = await inquirer.prompt([
        {
            type: 'number',
            name: 'length',
            message: chalk.magenta('Enter desired password length:'),
            default: 16,
        },
        {
            type: 'confirm',
            name: 'includeNumbers',
            message: chalk.magenta('Include numbers?'),
            default: true,
        },
        {
            type: 'confirm',
            name: 'includeSymbols',
            message: chalk.magenta('Include symbols?'),
            default: true,
        },
        {
            type: 'confirm',
            name: 'includeUppercase',
            message: chalk.magenta('Include uppercase letters?'),
            default: true,
        },
        {
            type: 'confirm',
            name: 'includeLowercase',
            message: chalk.magenta('Include lowercase letters?'),
            default: true,
        },
    ]);

    const password = generatePassword({
        length,
        numbers: includeNumbers,
        symbols: includeSymbols,
        uppercase: includeUppercase,
        lowercase: includeLowercase,
    });

    console.log(chalk.yellow(`\nGenerated Password: ${password}`));

    const { action } = await inquirer.prompt([
        {
            type: 'list',
            name: 'action',
            message: chalk.magenta('What would you like to do with the generated password?'),
            choices: [
                '📋 Copy to Clipboard',
                '💾 Save Password',
                '❌ Cancel',
            ],
        },
    ]);

    if (action === '📋 Copy to Clipboard') {
        await clipboardy.write(password);
        console.log(chalk.green('\nPassword copied to clipboard!'));
    } else if (action === '💾 Save Password') {
        const { site, username } = await inquirer.prompt([
            {
                type: 'input',
                name: 'site',
                message: chalk.magenta('Enter site:'),
            },
            {
                type: 'input',
                name: 'username',
                message: chalk.magenta('Enter username:'),
            },
        ]);

        // Add category selection
        const category = await selectCategory();
        
        passwords.push({ site, username, password, category });
        await savePasswords(passwords);

        console.log(chalk.green('\n💾 Generated password saved successfully!'));
    }

    await pauseMenu();
};

const viewPasswords = async () => {
    if (passwords.length === 0) {
        console.log(chalk.red('\n[❌] No passwords stored.'));
        await pauseMenu();
        return;
    }

    while (true) {  // Main viewing loop
        console.clear();
        console.log(chalk.cyan.bold(`
╔════════════════════════════════════════════════════╗
║             🔐  STORED PASSWORDS  🔐              ║
╚════════════════════════════════════════════════════╝
`));

        // Create choices array with category headers and passwords
        const choices = [];
        
        // Handle passwords with no category first
        const uncategorizedPasswords = passwords.filter(p => !p.category);
        if (uncategorizedPasswords.length > 0) {
            choices.push(new inquirer.Separator(chalk.yellow(`\n📂 No Category (${uncategorizedPasswords.length} passwords)`)));
            uncategorizedPasswords.forEach((entry) => {
                const actualIndex = passwords.findIndex(p => 
                    p.site === entry.site && 
                    p.username === entry.username && 
                    p.password === entry.password
                );
                choices.push({
                    name: chalk.cyan(`  ⟨${String(actualIndex + 1).padStart(2, '0')}⟩ → ${entry.site.padEnd(15)} | ${entry.username}`),
                    value: actualIndex,
                    short: entry.site
                });
            });
        }

        // Handle categorized passwords
        for (const category of categories) {
            const categoryPasswords = passwords.filter(p => p.category === category);
            if (categoryPasswords.length > 0) {
                choices.push(new inquirer.Separator(chalk.yellow(`\n📂 ${category} (${categoryPasswords.length} passwords)`)));
                
                categoryPasswords.forEach((entry) => {
                    const actualIndex = passwords.findIndex(p => 
                        p.site === entry.site && 
                        p.username === entry.username && 
                        p.password === entry.password
                    );
                    choices.push({
                        name: chalk.cyan(`  ⟨${String(actualIndex + 1).padStart(2, '0')}⟩ → ${entry.site.padEnd(15)} | ${entry.username}`),
                        value: actualIndex,
                        short: entry.site
                    });
                });
            }
        }

        console.log(chalk.cyan('📜 Total Passwords:', passwords.length));
        console.log(chalk.cyan('📂 Categories:', categories.length));
        console.log(chalk.cyan('\n--------------------------------------------------'));

        const { index } = await inquirer.prompt([
            {
                type: 'list',
                name: 'index',
                message: chalk.magenta('🔍 Select a password:'),
                choices: [...choices, new inquirer.Separator(), { name: '↩️ Back to Main Menu', value: 'back' }],
                pageSize: 15
            },
        ]);

        if (index === 'back') {
            return await mainMenu();
        }

        let continueViewing = true;
        while (continueViewing) {
            const selectedPassword = passwords[index];
            
            console.clear();
            console.log(chalk.green(`
╔════════════════════════════════════════════════════╗
║               🔑  PASSWORD DETAILS  🔑            ║
╚════════════════════════════════════════════════════╝
`));
            console.log(chalk.green(`🌐 Site: ${selectedPassword.site}`));
            console.log(chalk.green(`👤 Username: ${selectedPassword.username}`));
            console.log(chalk.green(`🔑 Password: ${selectedPassword.password}`));
            console.log(chalk.green(`📁 Category: ${selectedPassword.category || 'No Category'}`));
            
            const { action } = await inquirer.prompt([
                {
                    type: 'list',
                    name: 'action',
                    message: chalk.magenta('Choose an action:'),
                    choices: [
                        '📋 Copy Password to Clipboard',
                        '✏️ Change Category',
                        '↩️ Back to List'
                    ]
                }
            ]);

            switch (action) {
                case '📋 Copy Password to Clipboard':
                    await clipboardy.write(selectedPassword.password);
                    console.log(chalk.green('\n✔ Password copied to clipboard!'));
                    await new Promise(resolve => setTimeout(resolve, 1500));
                    break;
                    
                case '✏️ Change Category':
                    const newCategory = await selectCategory();
                    if (newCategory !== null) {
                        passwords[index] = { ...selectedPassword, category: newCategory };
                        await savePasswords(passwords);
                        console.log(chalk.green('\n✔ Category updated successfully!'));
                        await new Promise(resolve => setTimeout(resolve, 1500));
                    }
                    continueViewing = false;  // Return to password list
                    break;
                    
                case '↩️ Back to List':
                    continueViewing = false;  // Return to password list
                    break;
            }
        }
    }
};


const exportBackup = async () => {
    console.clear();
    console.log(chalk.hex('#9D4EDD')('Export Backup\n'));

    const { filename } = await inquirer.prompt([
        {
            type: 'input',
            name: 'filename',
            message: 'Enter backup filename:',
            default: `backup-${new Date().toISOString().split('T')[0]}.json`
        }
    ]);

    try {
        await fs.writeFile(filename, JSON.stringify(passwords, null, 2));
        console.log(chalk.green(`\n💾 Backup saved to ${filename}`));
    } catch (error) {
        console.log(chalk.red('\n❌ Error creating backup:', error.message));
    }

    await pauseMenu();
};

const passwordCheck = async () => {
    console.clear();
    console.log(chalk.hex('#9D4EDD')('Password Strength Check\n'));

    const { password } = await inquirer.prompt([
        {
            type: 'password',
            name: 'password',
            message: 'Enter password to check:'
        }
    ]);

    const strength = checkPasswordStrength(password);
    const strengthColor = {
        'Weak': '#FF0000',
        'Medium': '#FFA500',
        'Strong': '#00FF00'
    }[strength];

    console.log(chalk.hex(strengthColor)(`\n🔑 Password Strength: ${strength}`));
    await pauseMenu();
};

const deletePassword = async () => {
    if (passwords.length === 0) {
        console.clear();
        console.log(chalk.red(`
╔════════════════════════════════════════════════════╗
║           🚫 NO PASSWORDS TO DELETE 🚫            ║
╚════════════════════════════════════════════════════╝
`));
        await pauseMenu();
        return;
    }

    console.clear();
    console.log(chalk.cyan.bold(`
╔════════════════════════════════════════════════════╗
║         🗑️  DELETE A STORED PASSWORD  🗑️          ║
╚════════════════════════════════════════════════════╝
`));

    // Display stored passwords in a list format
    passwords.forEach((entry, index) => {
        console.log(chalk.cyan(`⟨${String(index + 1).padStart(2, '0')}⟩ → [${entry.site.padEnd(10)} | ${entry.username}]`));
    });

    console.log(chalk.cyan('\n--------------------------------------------------'));
    console.log(chalk.cyan('📜 Use arrow keys to navigate and select an option.'));
    console.log(chalk.cyan('--------------------------------------------------\n'));

    // Prompt user to select a password to delete
    const { index } = await inquirer.prompt([
        {
            type: 'list',
            name: 'index',
            message: chalk.magenta('❌ Select a password to delete:'),
            choices: passwords.map((entry, idx) => ({
                name: `⟨${String(idx + 1).padStart(2, '0')}⟩ → [${entry.site.padEnd(10)} | ${entry.username}]`,
                value: idx,
            })),
        },
    ]);

    // Confirm deletion
    const { confirmDelete } = await inquirer.prompt([
        {
            type: 'confirm',
            name: 'confirmDelete',
            message: chalk.red.bold(`⚠️ Are you sure you want to delete ⟨${String(index + 1).padStart(2, '0')}⟩ → [${passwords[index].site} | ${passwords[index].username}]?`),
        },
    ]);

    if (confirmDelete) {
        // Delete the selected password
        const deletedPassword = passwords.splice(index, 1);
        await savePasswords(passwords);

        console.clear();
        console.log(chalk.green(`
╔════════════════════════════════════════════════════╗
║       ✅ PASSWORD DELETED SUCCESSFULLY! ✅        ║
╚════════════════════════════════════════════════════╝
`));
        console.log(chalk.green(`Deleted: 🌐 Site: ${deletedPassword[0].site} | 👤 Username: ${deletedPassword[0].username}\n`));
    } else {
        console.log(chalk.yellow('\n❌ Deletion canceled.'));
    }

    await pauseMenu();
};

const pauseMenu = async () => {
    await inquirer.prompt([
        {
            type: 'input',
            name: 'pause',
            message: chalk.magenta('\nPress Enter to continue...'),
        },
    ]);
    await mainMenu();
};

export { showLoadingScreen, ASCII_HEADER };

// Initialize and run
(async () => {
    passwords = await loadPasswords();
    categories = await loadCategories();
    await showLoadingScreen();
    await mainMenu();
})();