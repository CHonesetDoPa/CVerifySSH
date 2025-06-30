let currentChallengeId = null;
let currentChallenge = null;

// 页面加载时检查服务器状态
window.addEventListener('load', function() {
    checkStatus();
});

// 获取挑战
async function getChallenge() {
    const btn = document.getElementById('getChallengeBtn');
    btn.disabled = true;
    btn.innerHTML = '<span class="loading"></span>获取中...';

    try {
        const response = await fetch('/api/challenge', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (data.success) {
            currentChallengeId = data.challengeId;
            currentChallenge = data;
            
            // 显示命令
            document.getElementById('command').textContent = data.command;
            document.getElementById('commandBox').style.display = 'block';
            document.getElementById('commandInfo').style.display = 'block';
            
            // 更新步骤状态
            updateStepStatus(1, 'completed');
            updateStepStatus(2, 'active');
            updateStepStatus(3, 'active');
            
            document.getElementById('verifyBtn').disabled = false;
            document.getElementById('currentChallenge').textContent = data.challengeId.substring(0, 8) + '...';
            
            showAlert('success', '挑战获取成功！请在终端中执行上述命令。');
        } else {
            showAlert('error', '获取挑战失败: ' + data.error);
        }
    } catch (error) {
        showAlert('error', '网络错误: ' + error.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="material-icons icon">play_arrow</i>获取挑战';
        updateLastUpdate();
    }
}

// 验证签名
async function verifySignature() {
    const publicKey = document.getElementById('publicKey').value.trim();
    const signature = document.getElementById('signature').value.trim();

    if (!publicKey || !signature) {
        showAlert('error', '请填写SSH公钥和签名');
        return;
    }

    if (!currentChallengeId) {
        showAlert('error', '请先获取挑战');
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
                signature: signature
            })
        });

        const data = await response.json();

        if (data.success) {
            updateStepStatus(3, 'completed');
            showAlert('success', '🎉 验证成功！您已通过人机验证。验证时间: ' + data.timestamp);
            
            // 重置表单
            resetForm();
        } else {
            showAlert('error', '验证失败: ' + data.error);
        }
    } catch (error) {
        showAlert('error', '网络错误: ' + error.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="material-icons icon">verified_user</i>验证签名';
        updateLastUpdate();
    }
}

// 检查服务器状态
async function checkStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();

        if (data.success) {
            document.getElementById('serverStatus').textContent = '运行正常';
            document.getElementById('serverStatus').style.color = '#4CAF50';
            showAlert('info', `服务器运行正常 - 版本: ${data.version}, 活跃挑战: ${data.activeChallenges}`);
        } else {
            document.getElementById('serverStatus').textContent = '状态未知';
            document.getElementById('serverStatus').style.color = '#f44336';
        }
    } catch (error) {
        document.getElementById('serverStatus').textContent = '连接失败';
        document.getElementById('serverStatus').style.color = '#f44336';
        showAlert('error', '无法连接到服务器: ' + error.message);
    }
    updateLastUpdate();
}

// 复制命令
function copyCommand() {
    const command = document.getElementById('command').textContent;
    navigator.clipboard.writeText(command).then(() => {
        showAlert('info', '命令已复制到剪贴板');
    }).catch(() => {
        showAlert('error', '复制失败，请手动复制命令');
    });
}

// 更新步骤状态
function updateStepStatus(stepNumber, status) {
    const step = document.getElementById(`step${stepNumber}`);
    step.className = `step ${status}`;
}

// 显示提示信息
function showAlert(type, message) {
    const resultArea = document.getElementById('resultArea');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type}`;
    alert.innerHTML = message.replace(/\n/g, '<br>');
    
    // 清除之前的提示
    resultArea.innerHTML = '';
    resultArea.appendChild(alert);
    
    // 滚动到结果区域
    alert.scrollIntoView({ behavior: 'smooth' });
}

// 重置表单
function resetForm() {
    document.getElementById('publicKey').value = '';
    document.getElementById('signature').value = '';
    currentChallengeId = null;
    currentChallenge = null;
    document.getElementById('currentChallenge').textContent = '无';
    
    // 重置步骤状态
    updateStepStatus(1, 'active');
    updateStepStatus(2, '');
    updateStepStatus(3, '');
    
    document.getElementById('verifyBtn').disabled = true;
    document.getElementById('commandBox').style.display = 'none';
    document.getElementById('commandInfo').style.display = 'none';
}

// 更新最后更新时间
function updateLastUpdate() {
    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
}
