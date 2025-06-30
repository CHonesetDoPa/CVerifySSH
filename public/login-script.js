let currentChallengeId = null;
let currentUsername = null;
let loginStartTime = null;

// 页面加载时的初始化
window.addEventListener('load', function() {
    // 检查是否已经登录
    checkLoginStatus();
    
    // 为用户名输入框添加回车监听
    document.getElementById('username').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            initiateLogin();
        }
    });
    
    // 为表单字段添加实时验证
    document.getElementById('publicKey').addEventListener('input', validateForm);
    document.getElementById('signature').addEventListener('input', validateForm);
});

// 检查登录状态
function checkLoginStatus() {
    const savedLogin = localStorage.getItem('sshLoginSession');
    if (savedLogin) {
        try {
            const loginData = JSON.parse(savedLogin);
            if (Date.now() - loginData.timestamp < 24 * 60 * 60 * 1000) { // 24小时有效
                showSuccessPage(loginData);
                return;
            }
        } catch (e) {
            localStorage.removeItem('sshLoginSession');
        }
    }
}

// 开始登录流程
async function initiateLogin() {
    const username = document.getElementById('username').value.trim();
    
    if (!username) {
        showAlert('error', '请输入用户名');
        return;
    }
    
    currentUsername = username;
    loginStartTime = Date.now();
    
    const btn = document.getElementById('loginBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="loading"></span>获取验证挑战...';
    
    try {
        // 获取登录挑战
        const response = await fetch('/api/challenge', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                purpose: 'login',
                username: username
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentChallengeId = data.challengeId;
            
            // 显示验证区域
            document.getElementById('verificationSection').style.display = 'block';
            document.getElementById('challengeInfo').style.display = 'block';
            document.getElementById('command').textContent = data.command;
            document.getElementById('verifyBtn').style.display = 'inline-flex';
            
            // 隐藏登录按钮
            btn.style.display = 'none';
            
            // 滚动到验证区域
            document.getElementById('verificationSection').scrollIntoView({ 
                behavior: 'smooth', 
                block: 'center' 
            });
            
            showAlert('success', `🔑 登录挑战已生成！请使用您的SSH私钥对消息进行签名。`);
        } else {
            throw new Error(data.error || '获取挑战失败');
        }
    } catch (error) {
        showAlert('error', '获取登录挑战失败: ' + error.message);
        btn.disabled = false;
        btn.innerHTML = '<i class="material-icons icon">login</i>开始登录';
    }
}

// 验证登录
async function verifyLogin() {
    const publicKey = document.getElementById('publicKey').value.trim();
    const signature = document.getElementById('signature').value.trim();
    
    if (!publicKey || !signature) {
        showAlert('error', '请填写SSH公钥和签名');
        return;
    }
    
    if (!currentChallengeId || !currentUsername) {
        showAlert('error', '登录会话已失效，请重新开始');
        resetLogin();
        return;
    }
    
    const btn = document.getElementById('verifyBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="loading"></span>验证中...';
    
    try {
        const response = await fetch('/api/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                challengeId: currentChallengeId,
                publicKey: publicKey,
                signature: signature,
                username: currentUsername
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // 登录成功
            const loginData = {
                username: currentUsername,
                timestamp: Date.now(),
                loginTime: new Date().toLocaleString(),
                keyType: data.keyType || '未知',
                challengeId: currentChallengeId,
                sessionId: data.sessionId
            };
            
            // 保存登录状态
            localStorage.setItem('sshLoginSession', JSON.stringify(loginData));
            
            // 显示成功页面
            showSuccessPage(loginData);
            
        } else {
            // 显示详细的错误信息，包括剩余尝试次数
            let errorMessage = data.error || '验证失败';
            if (data.remainingAttempts !== undefined) {
                errorMessage += `（剩余尝试次数：${data.remainingAttempts}）`;
            }
            throw new Error(errorMessage);
        }
    } catch (error) {
        showAlert('error', '登录验证失败: ' + error.message);
        btn.disabled = false;
        btn.innerHTML = '<i class="material-icons icon">check_circle</i>验证登录';
    }
}

// 显示成功页面
function showSuccessPage(loginData) {
    document.getElementById('displayUsername').textContent = loginData.username;
    document.getElementById('loginTime').textContent = loginData.loginTime;
    document.getElementById('keyType').textContent = loginData.keyType;
    document.getElementById('welcomeMessage').textContent = `欢迎回来，${loginData.username}！`;
    
    document.getElementById('successPage').style.display = 'flex';
}

// 退出登录
function logout() {
    localStorage.removeItem('sshLoginSession');
    document.getElementById('successPage').style.display = 'none';
    resetLogin();
    showAlert('info', '已安全退出登录');
}

// 进入控制台（模拟）
function goToDashboard() {
    showAlert('info', '正在跳转到用户控制台...');
    // 这里可以跳转到实际的用户控制台页面
    setTimeout(() => {
        window.open('/?dashboard=true', '_blank');
    }, 1000);
}

// 重置登录状态
function resetLogin() {
    currentChallengeId = null;
    currentUsername = null;
    loginStartTime = null;
    
    // 重置表单
    document.getElementById('username').value = '';
    document.getElementById('publicKey').value = '';
    document.getElementById('signature').value = '';
    
    // 重置UI
    document.getElementById('verificationSection').style.display = 'none';
    document.getElementById('challengeInfo').style.display = 'none';
    document.getElementById('loginBtn').style.display = 'inline-flex';
    document.getElementById('loginBtn').disabled = false;
    document.getElementById('loginBtn').innerHTML = '<i class="material-icons icon">login</i>开始登录';
    document.getElementById('verifyBtn').style.display = 'none';
    document.getElementById('verifyBtn').disabled = true;
    
    // 清除状态显示
    document.getElementById('statusArea').innerHTML = '';
}

// 复制命令
function copyCommand() {
    const command = document.getElementById('command').textContent;
    navigator.clipboard.writeText(command).then(() => {
        showAlert('success', '✅ 命令已复制到剪贴板');
        
        // 临时改变按钮文本
        const btn = document.querySelector('.copy-btn');
        const originalText = btn.textContent;
        btn.textContent = '已复制';
        btn.style.background = '#4CAF50';
        
        setTimeout(() => {
            btn.textContent = originalText;
            btn.style.background = '';
        }, 2000);
    }).catch(() => {
        showAlert('error', '复制失败，请手动复制命令');
    });
}

// 表单验证
function validateForm() {
    const publicKey = document.getElementById('publicKey').value.trim();
    const signature = document.getElementById('signature').value.trim();
    const verifyBtn = document.getElementById('verifyBtn');
    
    // 简单检查是否有内容，具体验证交给后端
    const isValid = publicKey.length > 0 && signature.length > 0 && currentChallengeId;
    verifyBtn.disabled = !isValid;
}

// 显示提示信息
function showAlert(type, message) {
    const statusArea = document.getElementById('statusArea');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.innerHTML = message;
    
    // 清除之前的提示
    statusArea.innerHTML = '';
    statusArea.appendChild(alert);
    
    // 自动隐藏成功和信息提示
    if (type === 'success' || type === 'info') {
        setTimeout(() => {
            if (alert.parentNode) {
                alert.style.transition = 'opacity 0.3s ease-out';
                alert.style.opacity = '0';
                setTimeout(() => {
                    if (alert.parentNode) {
                        alert.parentNode.removeChild(alert);
                    }
                }, 300);
            }
        }, 5000);
    }
    
    // 滚动到提示区域
    alert.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// 键盘快捷键支持
document.addEventListener('keydown', function(e) {
    // Ctrl+Enter 快速验证
    if (e.ctrlKey && e.key === 'Enter') {
        const verifyBtn = document.getElementById('verifyBtn');
        if (verifyBtn.style.display !== 'none' && !verifyBtn.disabled) {
            verifyLogin();
        }
    }
    
    // Esc 重置登录
    if (e.key === 'Escape') {
        if (document.getElementById('successPage').style.display === 'flex') {
            logout();
        } else {
            resetLogin();
        }
    }
});

// 页面离开时的确认
window.addEventListener('beforeunload', function(e) {
    if (currentChallengeId && !document.getElementById('successPage').style.display) {
        e.preventDefault();
        e.returnValue = '登录流程尚未完成，确定要离开吗？';
        return '登录流程尚未完成，确定要离开吗？';
    }
});

// 自动保存表单数据（临时）
function autoSaveForm() {
    const formData = {
        username: document.getElementById('username').value,
        publicKey: document.getElementById('publicKey').value,
        timestamp: Date.now()
    };
    
    sessionStorage.setItem('sshLoginForm', JSON.stringify(formData));
}

// 恢复表单数据
function restoreForm() {
    const savedForm = sessionStorage.getItem('sshLoginForm');
    if (savedForm) {
        try {
            const formData = JSON.parse(savedForm);
            // 只恢复最近10分钟内的数据
            if (Date.now() - formData.timestamp < 10 * 60 * 1000) {
                document.getElementById('username').value = formData.username || '';
                document.getElementById('publicKey').value = formData.publicKey || '';
            }
        } catch (e) {
            sessionStorage.removeItem('sshLoginForm');
        }
    }
}

// 页面加载时恢复表单
window.addEventListener('load', restoreForm);

// 定期自动保存
setInterval(autoSaveForm, 30000); // 每30秒保存一次
