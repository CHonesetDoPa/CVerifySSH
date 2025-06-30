let isRunning = false;
let isGenerating = false;

async function runSelfTest() {
    if (isRunning) return;
    
    isRunning = true;
    const runBtn = document.getElementById('runTestBtn');
    const status = document.getElementById('status');
    const loadingState = document.getElementById('loadingState');
    const testsContainer = document.getElementById('testsContainer');
    const errorContainer = document.getElementById('errorContainer');
    const summarySection = document.getElementById('summarySection');
    
    // 更新UI状态
    runBtn.disabled = true;
    status.textContent = '运行中...';
    loadingState.innerHTML = `
        <div class="spinner"></div>
        <div>正在执行自检测，请稍候...</div>
    `;
    loadingState.style.display = 'block';
    testsContainer.style.display = 'none';
    errorContainer.style.display = 'none';
    summarySection.style.display = 'none';
    
    try {
        const response = await fetch('/api/self-test');
        const data = await response.json();
        
        if (data.success) {
            displayTestResults(data);
            status.textContent = data.allPassed ? '全部通过' : '部分失败';
        } else {
            throw new Error(data.error || '自检测失败');
        }
        
    } catch (error) {
        console.error('自检测错误:', error);
        displayError(error.message);
        status.textContent = '执行失败';
    } finally {
        isRunning = false;
        runBtn.disabled = false;
        loadingState.style.display = 'none';
        document.getElementById('lastRun').textContent = new Date().toLocaleTimeString();
    }
}

async function generateKeyPair() {
    if (isGenerating) return;
    
    isGenerating = true;
    const generateBtn = document.getElementById('generateKeyBtn');
    const keypairSection = document.getElementById('keypairSection');
    
    generateBtn.disabled = true;
    generateBtn.innerHTML = '<span class="spinner" style="width: 16px; height: 16px; border-width: 2px; margin-right: 8px;"></span>生成中...';
    
    try {
        const response = await fetch('/api/generate-keypair', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            displayKeyPair(data.keyPair);
            keypairSection.style.display = 'block';
        } else {
            throw new Error(data.error || '密钥生成失败');
        }
        
    } catch (error) {
        console.error('密钥生成错误:', error);
        alert('密钥生成失败: ' + error.message);
    } finally {
        isGenerating = false;
        generateBtn.disabled = false;
        generateBtn.innerHTML = '<span class="material-icons">vpn_key</span>生成测试密钥对';
    }
}

function displayTestResults(data) {
    const testsContainer = document.getElementById('testsContainer');
    const summarySection = document.getElementById('summarySection');
    
    // 更新概览
    document.getElementById('totalTests').querySelector('.summary-value').textContent = data.summary.total;
    document.getElementById('passedTests').querySelector('.summary-value').textContent = data.summary.passed;
    document.getElementById('failedTests').querySelector('.summary-value').textContent = data.summary.failed;
    
    const overallStatus = document.getElementById('overallStatus');
    if (data.allPassed) {
        overallStatus.className = 'summary-item success';
        overallStatus.querySelector('.summary-value').textContent = '✓';
        overallStatus.querySelector('.summary-label').textContent = '全部通过';
    } else {
        overallStatus.className = 'summary-item warning';
        overallStatus.querySelector('.summary-value').textContent = '⚠';
        overallStatus.querySelector('.summary-label').textContent = '存在问题';
    }
    
    // 显示详细结果
    testsContainer.innerHTML = data.tests.map(test => {
        const statusClass = test.passed ? 'passed' : 'failed';
        const icon = test.passed ? '✓' : '✗';
        
        let testDataHtml = '';
        if (test.keyPair) {
            testDataHtml = `
                <div class="test-data">
                    <h4>生成的密钥对信息:</h4>
                    <div class="key-value"><strong>公钥类型:</strong> ${test.keyPair.publicKey.split(' ')[0]}</div>
                    <div class="key-value"><strong>测试消息:</strong> ${test.keyPair.message}</div>
                    <div class="key-value"><strong>命名空间:</strong> ${test.keyPair.namespace}</div>
                    <div class="key-value"><strong>公钥:</strong> ${test.keyPair.publicKey}</div>
                    <div class="key-value"><strong>签名:</strong></div>
                    <pre style="white-space: pre-wrap; margin-top: 5px;">${test.keyPair.signature}</pre>
                </div>
            `;
        }
        
        return `
            <div class="test-item ${statusClass}">
                <div class="test-header">
                    <div class="test-icon ${statusClass}">${icon}</div>
                    <div class="test-name">${test.name}</div>
                </div>
                <div class="test-details">${test.details}</div>
                ${testDataHtml}
            </div>
        `;
    }).join('');
    
    testsContainer.style.display = 'block';
    summarySection.style.display = 'block';
}

function displayKeyPair(keyPair) {
    const keypairContainer = document.getElementById('keypairContainer');
    
    keypairContainer.innerHTML = `
        <div style="margin-bottom: 20px; padding: 15px; background: #e8f5e8; border-radius: 8px; border-left: 4px solid #4CAF50;">
            <h4 style="margin-bottom: 10px; color: #2e7d32;">✓ Ed25519密钥对生成成功</h4>
            <p style="color: #666; margin-bottom: 0;">密钥类型: ${keyPair.keyType.toUpperCase()}</p>
        </div>
        
        <div class="test-data">
            <h4>公钥 (用于验证):</h4>
            <div style="background: white; padding: 10px; border: 1px solid #ddd; border-radius: 4px; margin: 10px 0; word-break: break-all;">
                ${keyPair.publicKey}
            </div>
            <button onclick="copyToClipboard('${keyPair.publicKey}')" class="btn" style="font-size: 0.9rem; padding: 8px 16px;">
                <span class="material-icons" style="font-size: 16px;">content_copy</span>
                复制公钥
            </button>
        </div>
        
        <div class="test-data" style="margin-top: 20px;">
            <h4>私钥 (请妥善保管，仅供测试使用):</h4>
            <div style="background: white; padding: 10px; border: 1px solid #ddd; border-radius: 4px; margin: 10px 0; white-space: pre-wrap; font-family: monospace; font-size: 0.9rem;">
${keyPair.privateKey}</div>
            <button onclick="copyToClipboard(\`${keyPair.privateKey}\`)" class="btn" style="font-size: 0.9rem; padding: 8px 16px;">
                <span class="material-icons" style="font-size: 16px;">content_copy</span>
                复制私钥
            </button>
        </div>
        
        <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-radius: 8px; border-left: 4px solid #ff9800;">
            <h4 style="margin-bottom: 10px; color: #e65100;">⚠️ 安全提醒</h4>
            <ul style="margin: 0; padding-left: 20px; color: #666;">
                <li>这是临时生成的测试密钥对，请勿用于生产环境</li>
                <li>私钥应当妥善保管，不要泄露给他人</li>
                <li>建议测试完成后删除这些密钥</li>
            </ul>
        </div>
    `;
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // 显示复制成功提示
        const toast = document.createElement('div');
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: #4CAF50;
            color: white;
            padding: 12px 20px;
            border-radius: 8px;
            z-index: 10000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        `;
        toast.textContent = '已复制到剪贴板';
        document.body.appendChild(toast);
        
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 2000);
    }).catch(err => {
        console.error('复制失败:', err);
        alert('复制失败，请手动选择并复制');
    });
}

function displayError(message) {
    const errorContainer = document.getElementById('errorContainer');
    errorContainer.innerHTML = `
        <div class="error">
            <h3 style="margin-bottom: 10px;">执行错误</h3>
            <p>${message}</p>
        </div>
    `;
    errorContainer.style.display = 'block';
}

// 页面加载时检查服务器状态
window.addEventListener('load', async () => {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();
        console.log('服务器状态:', data);
    } catch (error) {
        console.error('无法连接到服务器:', error);
        displayError('无法连接到服务器，请确保服务器正在运行');
    }
});
