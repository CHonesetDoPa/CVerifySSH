const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

// 安全配置
const SECURITY_CONFIG = {
    MAX_REQUEST_SIZE: '1MB',
    RATE_LIMIT_WINDOW: 15 * 60 * 1000, // 15分钟
    RATE_LIMIT_MAX: 100, // 每个IP最多100个请求
    CHALLENGE_TIMEOUT: 5 * 60 * 1000, // 5分钟
    SESSION_TIMEOUT: 24 * 60 * 60 * 1000, // 24小时
    MAX_USERNAME_LENGTH: 50,
    MAX_PUBLICKEY_LENGTH: 8192,
    MAX_SIGNATURE_LENGTH: 4096
};

// 请求频率限制存储
const rateLimitStore = new Map();

// 安全验证函数
const SecurityValidator = {
    // 验证用户名
    validateUsername(username) {
        if (!username || typeof username !== 'string') {
            return { valid: false, error: '用户名不能为空' };
        }
        
        const trimmed = username.trim();
        
        if (trimmed.length < 3 || trimmed.length > SECURITY_CONFIG.MAX_USERNAME_LENGTH) {
            return { valid: false, error: `用户名长度必须在3-${SECURITY_CONFIG.MAX_USERNAME_LENGTH}字符之间` };
        }
        
        // 防止注入攻击 - 只允许字母、数字、下划线、连字符
        if (!/^[a-zA-Z0-9_-]+$/.test(trimmed)) {
            return { valid: false, error: '用户名只能包含字母、数字、下划线和连字符' };
        }
        
        // 防止特殊关键字
        const forbiddenWords = ['admin', 'root', 'system', 'null', 'undefined', 'test', 'demo'];
        if (forbiddenWords.some(word => trimmed.toLowerCase().includes(word))) {
            return { valid: false, error: '用户名包含禁止使用的关键字' };
        }
        
        return { valid: true, value: trimmed };
    },

    // 验证SSH公钥
    validatePublicKey(publicKey) {
        if (!publicKey || typeof publicKey !== 'string') {
            return { valid: false, error: 'SSH公钥不能为空' };
        }
        
        const trimmed = publicKey.trim();
        
        if (trimmed.length > SECURITY_CONFIG.MAX_PUBLICKEY_LENGTH) {
            return { valid: false, error: 'SSH公钥过长' };
        }
        
        // 验证SSH公钥格式
        const sshKeyPattern = /^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)\s+[A-Za-z0-9+/]+=*(\s+.*)?$/;
        
        if (!sshKeyPattern.test(trimmed)) {
            return { valid: false, error: 'SSH公钥格式不正确' };
        }
        
        // 防止恶意字符
        if (/[<>&"'`$();|]/.test(trimmed)) {
            return { valid: false, error: 'SSH公钥包含非法字符' };
        }
        
        // 验证base64部分的有效性
        const parts = trimmed.split(/\s+/);
        if (parts.length < 2) {
            return { valid: false, error: 'SSH公钥格式不完整' };
        }
        
        try {
            // 验证base64编码是否有效
            const keyData = parts[1];
            if (!/^[A-Za-z0-9+/]+=*$/.test(keyData)) {
                return { valid: false, error: 'SSH公钥编码格式错误' };
            }
            
            // 尝试解码验证
            Buffer.from(keyData, 'base64');
        } catch (e) {
            return { valid: false, error: 'SSH公钥编码无效' };
        }
        
        return { valid: true, value: trimmed };
    },

    // 验证SSH签名
    validateSignature(signature) {
        if (!signature || typeof signature !== 'string') {
            return { valid: false, error: 'SSH签名不能为空' };
        }
        
        const trimmed = signature.trim();
        
        if (trimmed.length > SECURITY_CONFIG.MAX_SIGNATURE_LENGTH) {
            return { valid: false, error: 'SSH签名过长' };
        }
        
        // 验证签名格式
        if (!trimmed.includes('-----BEGIN SSH SIGNATURE-----') || 
            !trimmed.includes('-----END SSH SIGNATURE-----')) {
            return { valid: false, error: 'SSH签名格式不正确，必须包含完整的签名头尾' };
        }
        
        // 防止恶意字符
        if (/[<>&"'`$();|]/.test(trimmed)) {
            return { valid: false, error: 'SSH签名包含非法字符' };
        }
        
        // 验证签名结构
        const lines = trimmed.split('\n');
        const hasBegin = lines.some(line => line.trim() === '-----BEGIN SSH SIGNATURE-----');
        const hasEnd = lines.some(line => line.trim() === '-----END SSH SIGNATURE-----');
        
        if (!hasBegin || !hasEnd) {
            return { valid: false, error: 'SSH签名格式不完整' };
        }
        
        return { valid: true, value: trimmed };
    },

    // 验证挑战ID
    validateChallengeId(challengeId) {
        if (!challengeId || typeof challengeId !== 'string') {
            return { valid: false, error: '挑战ID不能为空' };
        }
        
        // UUID v4 格式验证
        const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        
        if (!uuidPattern.test(challengeId)) {
            return { valid: false, error: '挑战ID格式无效' };
        }
        
        return { valid: true, value: challengeId };
    },

    // 验证请求目的
    validatePurpose(purpose) {
        if (!purpose) {
            return { valid: true, value: 'verify' }; // 默认值
        }
        
        if (typeof purpose !== 'string') {
            return { valid: false, error: '请求目的格式错误' };
        }
        
        const allowedPurposes = ['verify', 'login', 'test'];
        const trimmed = purpose.trim().toLowerCase();
        
        if (!allowedPurposes.includes(trimmed)) {
            return { valid: false, error: '请求目的不被支持' };
        }
        
        return { valid: true, value: trimmed };
    }
};

// 请求频率限制中间件
function rateLimitMiddleware(req, res, next) {
    const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    
    // 清理过期记录
    for (const [ip, data] of rateLimitStore.entries()) {
        if (now - data.windowStart > SECURITY_CONFIG.RATE_LIMIT_WINDOW) {
            rateLimitStore.delete(ip);
        }
    }
    
    // 检查当前IP
    let ipData = rateLimitStore.get(clientIP);
    
    if (!ipData || now - ipData.windowStart > SECURITY_CONFIG.RATE_LIMIT_WINDOW) {
        // 新窗口或新IP
        ipData = {
            windowStart: now,
            requestCount: 1,
            lastRequest: now
        };
    } else {
        ipData.requestCount++;
        ipData.lastRequest = now;
    }
    
    rateLimitStore.set(clientIP, ipData);
    
    // 检查是否超过限制
    if (ipData.requestCount > SECURITY_CONFIG.RATE_LIMIT_MAX) {
        console.warn(`Rate limit exceeded for IP: ${clientIP}`);
        return res.status(429).json({
            success: false,
            error: '请求过于频繁，请稍后再试',
            retryAfter: Math.ceil((SECURITY_CONFIG.RATE_LIMIT_WINDOW - (now - ipData.windowStart)) / 1000)
        });
    }
    
    // 设置响应头
    res.set({
        'X-RateLimit-Limit': SECURITY_CONFIG.RATE_LIMIT_MAX,
        'X-RateLimit-Remaining': Math.max(0, SECURITY_CONFIG.RATE_LIMIT_MAX - ipData.requestCount),
        'X-RateLimit-Reset': new Date(ipData.windowStart + SECURITY_CONFIG.RATE_LIMIT_WINDOW).toISOString()
    });
    
    next();
}

// 安全响应头中间件
function securityHeadersMiddleware(req, res, next) {
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:",
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    });
    next();
}

// 中间件
app.use(securityHeadersMiddleware);
app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? ['https://yourdomain.com'] : true,
    credentials: true,
    optionsSuccessStatus: 200
}));
app.use(bodyParser.json({ 
    limit: SECURITY_CONFIG.MAX_REQUEST_SIZE,
    verify: (req, res, buf) => {
        // 防止JSON炸弹攻击
        if (buf.length > 1024 * 1024) { // 1MB
            throw new Error('Request body too large');
        }
    }
}));
app.use(bodyParser.urlencoded({ 
    extended: true, 
    limit: SECURITY_CONFIG.MAX_REQUEST_SIZE 
}));
app.use(rateLimitMiddleware);
app.use(express.static('public'));

// 存储挑战信息的内存缓存
const challenges = new Map();

// 安全监控和清理功能
const SecurityMonitor = {
    // 定期清理过期数据
    startCleanupScheduler() {
        setInterval(() => {
            this.cleanupExpiredChallenges();
            this.cleanupRateLimitData();
        }, 60000); // 每分钟清理一次
    },

    // 清理过期挑战
    cleanupExpiredChallenges() {
        const now = Date.now();
        let cleanedCount = 0;
        
        for (const [id, challenge] of challenges.entries()) {
            if (now - challenge.created > SECURITY_CONFIG.CHALLENGE_TIMEOUT) {
                challenges.delete(id);
                cleanedCount++;
            }
        }
        
        if (cleanedCount > 0) {
            console.log(`Cleaned up ${cleanedCount} expired challenges`);
        }
    },

    // 清理频率限制数据
    cleanupRateLimitData() {
        const now = Date.now();
        let cleanedCount = 0;
        
        for (const [ip, data] of rateLimitStore.entries()) {
            if (now - data.windowStart > SECURITY_CONFIG.RATE_LIMIT_WINDOW) {
                rateLimitStore.delete(ip);
                cleanedCount++;
            }
        }
        
        if (cleanedCount > 0) {
            console.log(`Cleaned up ${cleanedCount} expired rate limit entries`);
        }
    },

    // 获取系统状态
    getSystemStatus() {
        return {
            activeChallenges: challenges.size,
            activeRateLimitEntries: rateLimitStore.size,
            memory: process.memoryUsage(),
            uptime: process.uptime()
        };
    },

    // 记录可疑活动
    logSuspiciousActivity(ip, activity, details) {
        const timestamp = new Date().toISOString();
        const logEntry = `[${timestamp}] SUSPICIOUS: ${activity} from ${ip} - ${details}`;
        console.warn(logEntry);
        
        // 这里可以添加更多的安全日志记录，比如写入文件或发送告警
        // 例如：写入安全日志文件
        // fs.appendFileSync('/var/log/ssh-verify-security.log', logEntry + '\n');
    }
};

// 启动安全监控
SecurityMonitor.startCleanupScheduler();

// 生成挑战
app.post('/api/challenge', (req, res) => {
    try {
        const { purpose, username } = req.body;
        
        // 验证请求目的
        const purposeValidation = SecurityValidator.validatePurpose(purpose);
        if (!purposeValidation.valid) {
            return res.status(400).json({
                success: false,
                error: purposeValidation.error
            });
        }
        
        // 如果是登录请求，验证用户名
        if (purposeValidation.value === 'login') {
            const usernameValidation = SecurityValidator.validateUsername(username);
            if (!usernameValidation.valid) {
                return res.status(400).json({
                    success: false,
                    error: usernameValidation.error
                });
            }
        }
        
        const challengeId = uuidv4();
        const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
        
        // 生成安全的随机字符串
        const randomBytes = crypto.randomBytes(16).toString('hex');
        const timestamp = Date.now();
        
        // 根据用途生成不同的消息和命名空间
        let message, namespace;
        if (purposeValidation.value === 'login' && username) {
            const cleanUsername = SecurityValidator.validateUsername(username).value;
            message = `Login-${cleanUsername}-${timestamp}-${randomBytes}`;
            namespace = 'ssh-login';
        } else {
            message = `VerifySSH-${timestamp}-${randomBytes}`;
            namespace = 'ssh-verify';
        }
        
        // 存储挑战信息
        challenges.set(challengeId, {
            message,
            namespace,
            purpose: purposeValidation.value,
            username: purposeValidation.value === 'login' ? SecurityValidator.validateUsername(username).value : null,
            created: timestamp,
            verified: false,
            clientIP: clientIP,
            attempts: 0
        });

        // 清理过期挑战
        setTimeout(() => {
            challenges.delete(challengeId);
        }, SECURITY_CONFIG.CHALLENGE_TIMEOUT);

        // 记录日志
        console.log(`Challenge created: ${challengeId} for ${clientIP}, purpose: ${purposeValidation.value}`);

        res.json({
            success: true,
            challengeId,
            message,
            namespace,
            command: `echo -n "${message}" | ssh-keygen -Y sign -n ${namespace} -f ~/.ssh/your-private-key`,
            instructions: {
                step1: '使用上述命令对消息进行签名',
                step2: '提交你的SSH公钥内容（通常在 ~/.ssh/your-key.pub）',
                step3: '提交签名内容（以 -----BEGIN SSH SIGNATURE----- 开头）',
                note: '确保使用相同的私钥进行签名和提供对应的公钥'
            },
            expiresIn: SECURITY_CONFIG.CHALLENGE_TIMEOUT / 1000, // 秒
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('Challenge generation error:', error);
        res.status(500).json({
            success: false,
            error: '服务器内部错误'
        });
    }
});

// 验证签名
app.post('/api/verify', async (req, res) => {
    try {
        const { challengeId, publicKey, signature, username } = req.body;
        const clientIP = req.ip || req.connection.remoteAddress || 'unknown';
        const timestamp = Date.now();

        console.log(`验证请求来自 ${clientIP}:`, { 
            challengeId: challengeId?.substring(0, 8) + '...', 
            publicKeyLength: publicKey?.length, 
            signatureLength: signature?.length,
            username 
        });

        // 1. 验证挑战ID
        const challengeIdValidation = SecurityValidator.validateChallengeId(challengeId);
        if (!challengeIdValidation.valid) {
            console.warn(`Invalid challenge ID from ${clientIP}: ${challengeIdValidation.error}`);
            SecurityMonitor.logSuspiciousActivity(clientIP, 'INVALID_CHALLENGE_ID', challengeIdValidation.error);
            return res.status(400).json({
                success: false,
                error: challengeIdValidation.error
            });
        }

        // 2. 验证公钥
        const publicKeyValidation = SecurityValidator.validatePublicKey(publicKey);
        if (!publicKeyValidation.valid) {
            console.warn(`Invalid public key from ${clientIP}: ${publicKeyValidation.error}`);
            SecurityMonitor.logSuspiciousActivity(clientIP, 'INVALID_PUBLIC_KEY', publicKeyValidation.error);
            return res.status(400).json({
                success: false,
                error: publicKeyValidation.error
            });
        }

        // 3. 验证签名
        const signatureValidation = SecurityValidator.validateSignature(signature);
        if (!signatureValidation.valid) {
            console.warn(`Invalid signature from ${clientIP}: ${signatureValidation.error}`);
            return res.status(400).json({
                success: false,
                error: signatureValidation.error
            });
        }

        // 4. 获取挑战信息
        const challenge = challenges.get(challengeIdValidation.value);
        if (!challenge) {
            console.warn(`Challenge not found from ${clientIP}: ${challengeIdValidation.value}`);
            return res.status(400).json({
                success: false,
                error: '挑战不存在或已过期'
            });
        }

        // 5. 检查挑战状态
        if (challenge.verified) {
            console.warn(`Challenge already verified from ${clientIP}: ${challengeIdValidation.value}`);
            return res.status(400).json({
                success: false,
                error: '此挑战已被验证过'
            });
        }

        // 6. 检查IP匹配（可选，用于额外安全）
        if (process.env.NODE_ENV === 'production' && challenge.clientIP !== clientIP) {
            console.warn(`IP mismatch for challenge ${challengeIdValidation.value}: ${challenge.clientIP} vs ${clientIP}`);
            return res.status(403).json({
                success: false,
                error: '安全验证失败'
            });
        }

        // 7. 检查尝试次数
        challenge.attempts = (challenge.attempts || 0) + 1;
        if (challenge.attempts > 3) {
            console.warn(`Too many attempts for challenge ${challengeIdValidation.value} from ${clientIP}`);
            SecurityMonitor.logSuspiciousActivity(clientIP, 'TOO_MANY_ATTEMPTS', `Challenge: ${challengeIdValidation.value}, Attempts: ${challenge.attempts}`);
            challenges.delete(challengeIdValidation.value);
            return res.status(429).json({
                success: false,
                error: '尝试次数过多，请重新获取挑战'
            });
        }

        // 8. 如果是登录验证，检查用户名
        if (challenge.purpose === 'login') {
            const usernameValidation = SecurityValidator.validateUsername(username);
            if (!usernameValidation.valid || usernameValidation.value !== challenge.username) {
                console.warn(`Username mismatch for login challenge from ${clientIP}`);
                return res.status(400).json({
                    success: false,
                    error: '用户名验证失败'
                });
            }
        }

        // 9. 检查挑战是否过期
        if (timestamp - challenge.created > SECURITY_CONFIG.CHALLENGE_TIMEOUT) {
            console.warn(`Expired challenge ${challengeIdValidation.value} from ${clientIP}`);
            challenges.delete(challengeIdValidation.value);
            return res.status(400).json({
                success: false,
                error: '挑战已过期，请重新获取'
            });
        }

        console.log(`开始验证签名 for ${clientIP}...`);
        console.log('消息:', challenge.message);
        console.log('命名空间:', challenge.namespace);

        // 10. 验证SSH签名
        let isValid = false;
        try {
            isValid = await verifySSHSignature(
                challenge.message,
                challenge.namespace,
                publicKeyValidation.value,
                signatureValidation.value
            );
        } catch (verifyError) {
            console.error(`Signature verification error for ${clientIP}:`, verifyError);
            return res.status(500).json({
                success: false,
                error: '签名验证过程中发生错误'
            });
        }

        console.log(`验证结果 for ${clientIP}:`, isValid);

        if (isValid) {
            // 验证成功
            challenge.verified = true;
            challenge.verifiedAt = timestamp;
            challenge.verifiedIP = clientIP;
            
            // 记录成功日志
            console.log(`Verification successful for ${clientIP}, challenge: ${challengeIdValidation.value}, purpose: ${challenge.purpose}`);
            
            // 根据验证目的返回不同的响应
            if (challenge.purpose === 'login') {
                const sessionId = uuidv4();
                
                res.json({
                    success: true,
                    message: `登录验证成功！欢迎，${challenge.username}`,
                    timestamp: new Date().toISOString(),
                    loginType: 'ssh-key',
                    username: challenge.username,
                    sessionId: sessionId,
                    keyType: detectKeyType(publicKeyValidation.value),
                    expiresIn: SECURITY_CONFIG.SESSION_TIMEOUT / 1000 // 秒
                });
            } else {
                res.json({
                    success: true,
                    message: '验证成功！您已通过人机验证',
                    timestamp: new Date().toISOString(),
                    challengeId: challengeIdValidation.value,
                    keyType: detectKeyType(publicKeyValidation.value)
                });
            }
            
            // 延迟删除挑战（允许客户端处理响应）
            setTimeout(() => {
                challenges.delete(challengeIdValidation.value);
            }, 5000);
            
        } else {
            // 验证失败
            console.warn(`Verification failed for ${clientIP}, challenge: ${challengeIdValidation.value}, attempts: ${challenge.attempts}`);
            
            // 如果尝试次数过多，删除挑战
            if (challenge.attempts >= 3) {
                challenges.delete(challengeIdValidation.value);
                return res.status(429).json({
                    success: false,
                    error: '验证失败次数过多，请重新获取挑战'
                });
            }
            
            res.status(400).json({
                success: false,
                error: '签名验证失败，请检查：1) 公钥和私钥是否匹配 2) 签名是否正确生成 3) 消息是否完全一致',
                remainingAttempts: 3 - challenge.attempts
            });
        }

    } catch (error) {
        console.error('验证错误:', error);
        
        // 不暴露内部错误详情
        res.status(500).json({
            success: false,
            error: '服务器内部错误，请稍后重试'
        });
    }
});

// 检测SSH密钥类型的辅助函数
function detectKeyType(publicKey) {
    if (publicKey.startsWith('ssh-rsa')) {
        return 'RSA';
    } else if (publicKey.startsWith('ssh-ed25519')) {
        return 'Ed25519';
    } else if (publicKey.startsWith('ssh-dss')) {
        return 'DSA';
    } else if (publicKey.startsWith('ecdsa-sha2-')) {
        return 'ECDSA';
    } else {
        return '未知';
    }
}

// SSH签名验证函数
async function verifySSHSignature(message, namespace, publicKey, signature) {
    return new Promise((resolve) => {
        try {
            // 创建临时文件
            const tempDir = '/tmp/ssh-verify-' + Date.now() + '-' + Math.random().toString(36).substring(7);
            const publicKeyFile = path.join(tempDir, 'allowed_signers');
            const signatureFile = path.join(tempDir, 'signature.sig');
            const messageFile = path.join(tempDir, 'message.txt');

            // 创建临时目录
            if (!fs.existsSync(tempDir)) {
                fs.mkdirSync(tempDir, { recursive: true });
            }

            // 规范化公钥格式 - 确保公钥格式正确
            let normalizedPublicKey = publicKey.trim();
            if (!normalizedPublicKey.endsWith('\n')) {
                normalizedPublicKey += '\n';
            }

            // 规范化签名格式 - 确保签名是base64格式
            let normalizedSignature = signature.trim();
            if (!normalizedSignature.startsWith('-----BEGIN SSH SIGNATURE-----')) {
                // 如果不是完整的SSH签名格式，尝试包装
                normalizedSignature = `-----BEGIN SSH SIGNATURE-----\n${normalizedSignature}\n-----END SSH SIGNATURE-----\n`;
            }
            if (!normalizedSignature.endsWith('\n')) {
                normalizedSignature += '\n';
            }

            // 写入文件，使用allowed_signers格式
            // allowed_signers格式: user@domain ssh-rsa AAAAB3...
            const allowedSignersContent = `any ${normalizedPublicKey}`;
            fs.writeFileSync(publicKeyFile, allowedSignersContent);
            fs.writeFileSync(signatureFile, normalizedSignature);
            fs.writeFileSync(messageFile, message);

            // 设置文件权限
            fs.chmodSync(publicKeyFile, 0o600);
            fs.chmodSync(signatureFile, 0o600);
            fs.chmodSync(messageFile, 0o600);

            // 使用ssh-keygen验证签名
            const cmd = `ssh-keygen -Y verify -f "${publicKeyFile}" -I any -n "${namespace}" -s "${signatureFile}" < "${messageFile}"`;
            
            console.log('执行验证命令:', cmd);
            console.log('临时目录:', tempDir);
            
            exec(cmd, { timeout: 10000 }, (error, stdout, stderr) => {
                // 清理临时文件
                try {
                    fs.rmSync(tempDir, { recursive: true, force: true });
                } catch (cleanupError) {
                    console.error('清理临时文件失败:', cleanupError);
                }

                console.log('验证输出:', { stdout, stderr, error: error?.message });

                if (error) {
                    console.log('验证失败:', stderr || error.message);
                    resolve(false);
                } else {
                    console.log('验证成功:', stdout);
                    resolve(true);
                }
            });

        } catch (error) {
            console.error('签名验证过程出错:', error);
            resolve(false);
        }
    });
}

// 状态检查接口
app.get('/api/status', (req, res) => {
    const systemStatus = SecurityMonitor.getSystemStatus();
    
    res.json({
        success: true,
        server: 'SSH验证服务器',
        version: '1.2.0',
        timestamp: new Date().toISOString(),
        activeChallenges: systemStatus.activeChallenges,
        security: {
            rateLimitEntries: systemStatus.activeRateLimitEntries,
            maxRequestsPerWindow: SECURITY_CONFIG.RATE_LIMIT_MAX,
            challengeTimeout: SECURITY_CONFIG.CHALLENGE_TIMEOUT / 1000,
            sessionTimeout: SECURITY_CONFIG.SESSION_TIMEOUT / 1000
        },
        system: {
            uptime: Math.floor(systemStatus.uptime),
            memory: {
                used: Math.floor(systemStatus.memory.heapUsed / 1024 / 1024),
                total: Math.floor(systemStatus.memory.heapTotal / 1024 / 1024)
            }
        }
    });
});

// 自检测API端点
app.get('/api/self-test', async (req, res) => {
    try {
        console.log('开始执行自检测...');
        const testResults = await performSelfTest();
        
        const allPassed = testResults.every(test => test.passed);
        
        res.json({
            success: true,
            allPassed,
            timestamp: new Date().toISOString(),
            tests: testResults,
            summary: {
                total: testResults.length,
                passed: testResults.filter(test => test.passed).length,
                failed: testResults.filter(test => !test.passed).length
            }
        });
        
    } catch (error) {
        console.error('自检测执行失败:', error);
        res.status(500).json({
            success: false,
            error: '自检测执行失败: ' + error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// 生成ed25519密钥对API端点
app.post('/api/generate-keypair', async (req, res) => {
    try {
        const tempDir = '/tmp/ssh-keygen-' + Date.now() + '-' + Math.random().toString(36).substring(7);
        
        // 创建临时目录
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        
        const privateKeyFile = path.join(tempDir, 'temp_ed25519');
        const publicKeyFile = path.join(tempDir, 'temp_ed25519.pub');
        
        // 生成ed25519密钥对
        const keygenCmd = `ssh-keygen -t ed25519 -f "${privateKeyFile}" -N "" -C "temp@localhost"`;
        
        exec(keygenCmd, { timeout: 10000 }, (keygenError, keygenStdout, keygenStderr) => {
            if (keygenError) {
                // 清理临时文件
                try {
                    fs.rmSync(tempDir, { recursive: true, force: true });
                } catch (cleanupError) {
                    console.error('清理临时文件失败:', cleanupError);
                }
                
                return res.status(500).json({
                    success: false,
                    error: '密钥生成失败: ' + (keygenStderr || keygenError.message)
                });
            }
            
            try {
                // 读取生成的密钥对
                const privateKey = fs.readFileSync(privateKeyFile, 'utf8');
                const publicKey = fs.readFileSync(publicKeyFile, 'utf8').trim();
                
                // 清理临时文件
                fs.rmSync(tempDir, { recursive: true, force: true });
                
                res.json({
                    success: true,
                    keyPair: {
                        privateKey,
                        publicKey,
                        keyType: 'ed25519'
                    },
                    timestamp: new Date().toISOString(),
                    note: '这是临时生成的密钥对，仅供测试使用'
                });
                
            } catch (readError) {
                // 清理临时文件
                try {
                    fs.rmSync(tempDir, { recursive: true, force: true });
                } catch (cleanupError) {
                    console.error('清理临时文件失败:', cleanupError);
                }
                
                res.status(500).json({
                    success: false,
                    error: '读取密钥文件失败: ' + readError.message
                });
            }
        });
        
    } catch (error) {
        console.error('生成密钥对错误:', error);
        res.status(500).json({
            success: false,
            error: '生成密钥对失败: ' + error.message
        });
    }
});


// 自检测函数
async function performSelfTest() {
    const tests = [];
    
    // 测试1: 测试挑战生成
    tests.push(await testChallengeGeneration());
    
    // 测试2: 测试内存存储
    tests.push(await testMemoryStorage());
    
    // 测试3: 测试ed25519密钥对生成和验证
    tests.push(await testEd25519KeyPairVerification());

    return tests;
}

function testChallengeGeneration() {
    return new Promise((resolve) => {
        try {
            const challengeId = uuidv4();
            const message = `test-${Date.now()}`;
            challenges.set(challengeId, {
                message,
                namespace: 'test',
                created: Date.now(),
                verified: false
            });

            const retrieved = challenges.get(challengeId);
            const passed = retrieved && retrieved.message === message;
            
            // 清理测试数据
            challenges.delete(challengeId);

            resolve({
                name: '挑战生成测试',
                passed,
                details: passed ? '挑战生成和存储正常' : '挑战生成失败'
            });
        } catch (error) {
            resolve({
                name: '挑战生成测试',
                passed: false,
                details: `错误: ${error.message}`
            });
        }
    });
}

function testMemoryStorage() {
    return new Promise((resolve) => {
        try {
            const testKey = 'test-' + Date.now();
            const testValue = { test: true };
            
            challenges.set(testKey, testValue);
            const retrieved = challenges.get(testKey);
            const passed = retrieved && retrieved.test === true;
            
            challenges.delete(testKey);

            resolve({
                name: '内存存储测试',
                passed,
                details: passed ? '内存存储工作正常' : '内存存储失败'
            });
        } catch (error) {
            resolve({
                name: '内存存储测试',
                passed: false,
                details: `错误: ${error.message}`
            });
        }
    });
}

// 测试ed25519密钥对生成和验证
function testEd25519KeyPairVerification() {
    return new Promise((resolve) => {
        try {
            const tempDir = '/tmp/ssh-selftest-' + Date.now() + '-' + Math.random().toString(36).substring(7);
            
            // 创建临时目录
            if (!fs.existsSync(tempDir)) {
                fs.mkdirSync(tempDir, { recursive: true });
            }
            
            const privateKeyFile = path.join(tempDir, 'test_ed25519');
            const publicKeyFile = path.join(tempDir, 'test_ed25519.pub');
            
            // 生成ed25519密钥对
            const keygenCmd = `ssh-keygen -t ed25519 -f "${privateKeyFile}" -N "" -C "selftest@localhost"`;
            
            exec(keygenCmd, { timeout: 10000 }, (keygenError, keygenStdout, keygenStderr) => {
                if (keygenError) {
                    // 清理临时文件
                    try {
                        fs.rmSync(tempDir, { recursive: true, force: true });
                    } catch (cleanupError) {
                        console.error('清理临时文件失败:', cleanupError);
                    }
                    
                    resolve({
                        name: 'Ed25519密钥对生成测试',
                        passed: false,
                        details: `密钥生成失败: ${keygenStderr || keygenError.message}`
                    });
                    return;
                }
                
                // 读取生成的公钥
                let publicKey;
                try {
                    publicKey = fs.readFileSync(publicKeyFile, 'utf8').trim();
                } catch (readError) {
                    // 清理临时文件
                    try {
                        fs.rmSync(tempDir, { recursive: true, force: true });
                    } catch (cleanupError) {
                        console.error('清理临时文件失败:', cleanupError);
                    }
                    
                    resolve({
                        name: 'Ed25519密钥对生成测试',
                        passed: false,
                        details: `读取公钥失败: ${readError.message}`
                    });
                    return;
                }
                
                // 创建测试消息和命名空间
                const testMessage = `selftest-${Date.now()}-${Math.random().toString(36).substring(7)}`;
                const testNamespace = 'ssh-selftest';
                
                // 对消息进行签名
                const signCmd = `echo -n "${testMessage}" | ssh-keygen -Y sign -n ${testNamespace} -f "${privateKeyFile}"`;
                
                exec(signCmd, { timeout: 10000 }, async (signError, signStdout, signStderr) => {
                    if (signError) {
                        // 清理临时文件
                        try {
                            fs.rmSync(tempDir, { recursive: true, force: true });
                        } catch (cleanupError) {
                            console.error('清理临时文件失败:', cleanupError);
                        }
                        
                        resolve({
                            name: 'Ed25519密钥对生成测试',
                            passed: false,
                            details: `签名失败: ${signStderr || signError.message}`
                        });
                        return;
                    }
                    
                    // 验证签名
                    try {
                        const isValid = await verifySSHSignature(testMessage, testNamespace, publicKey, signStdout);
                        
                        // 清理临时文件
                        try {
                            fs.rmSync(tempDir, { recursive: true, force: true });
                        } catch (cleanupError) {
                            console.error('清理临时文件失败:', cleanupError);
                        }
                        
                        resolve({
                            name: 'Ed25519密钥对生成测试',
                            passed: isValid,
                            details: isValid ? 
                                `Ed25519密钥对生成、签名和验证全部成功` : 
                                '密钥对生成成功但验证失败',
                            keyPair: {
                                publicKey,
                                message: testMessage,
                                namespace: testNamespace,
                                signature: signStdout
                            }
                        });
                        
                    } catch (verifyError) {
                        // 清理临时文件
                        try {
                            fs.rmSync(tempDir, { recursive: true, force: true });
                        } catch (cleanupError) {
                            console.error('清理临时文件失败:', cleanupError);
                        }
                        
                        resolve({
                            name: 'Ed25519密钥对生成测试',
                            passed: false,
                            details: `验证过程出错: ${verifyError.message}`
                        });
                    }
                });
            });
            
        } catch (error) {
            resolve({
                name: 'Ed25519密钥对生成测试',
                passed: false,
                details: `测试过程出错: ${error.message}`
            });
        }
    });
}

// 测试验证端点（用于调试）
app.post('/api/test-verify', async (req, res) => {
    try {
        const { message, namespace, publicKey, signature } = req.body;

        console.log('测试验证请求:', { message, namespace, publicKeyLength: publicKey?.length, signatureLength: signature?.length });

        if (!message || !namespace || !publicKey || !signature) {
            return res.status(400).json({
                success: false,
                error: '缺少必要参数：message, namespace, publicKey, signature'
            });
        }

        const isValid = await verifySSHSignature(message, namespace, publicKey, signature);

        res.json({
            success: true,
            valid: isValid,
            message: isValid ? '测试验证成功' : '测试验证失败',
            details: {
                message,
                namespace,
                publicKeyType: publicKey.split(' ')[0],
                signatureValid: signature.includes('-----BEGIN SSH SIGNATURE-----')
            }
        });

    } catch (error) {
        console.error('测试验证错误:', error);
        res.status(500).json({
            success: false,
            error: '测试验证失败: ' + error.message
        });
    }
});

// 启动服务器
app.listen(PORT, () => {
    console.log(`🚀 SSH验证服务器启动成功！`);
    console.log(`📍 服务地址: http://localhost:${PORT}`);
    console.log(`🔧 API端点:`);
    console.log(`   POST /api/challenge - 获取验证挑战`);
    console.log(`   POST /api/verify - 验证签名`);
    console.log(`   POST /api/test-verify - 测试验证（调试用）`);
    console.log(`   GET  /api/status - 服务器状态`);
    console.log(`   GET  /api/self-test - 自检测`);
    
    // 启动时进行自检测
    setTimeout(async () => {
        try {
            const testResults = await performSelfTest();
            console.log('\n🔍 启动自检测结果:');
            testResults.forEach(test => {
                const status = test.passed ? '✅' : '❌';
                console.log(`   ${status} ${test.name}: ${test.details}`);
            });
        } catch (error) {
            console.error('❌ 自检测失败:', error.message);
        }
    }, 1000);
});

module.exports = app;