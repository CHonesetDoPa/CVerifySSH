# CVerifySSH不会验证码机！

验证码太简单了，机器人都会做，怎么办？

还好，聪明的CC发明了（指复刻了LSP IT的人机验证）不会验证码机！它可以让世界上所有的开发者都用SSH密钥验证身份！

- 优点
    + 比传统验证码更安全，机器人搞不定SSH签名
    + 对程序员友好，谁的电脑里还没几个SSH密钥
    + 无需第三方服务，防止验证码厂商偷窥你的隐私
    + 速度快，本地验证不用等网络<sub>（除非你的SSH坏了）</sub>
    + 界面好看，用了Material-UI呢

- 缺点
    + 普通用户可能不会用
    + 需要会敲命令行<sub>（不过程序员都会啦）</sub>

## 使用效果

我们先来试试生成一个挑战吧！

点击「获取挑战」，系统会给你这样的命令——

```bash
echo -n "VerifySSH-1735459200000-abc123" | ssh-keygen -Y sign -n ssh-verify -f ~/.ssh/id_ed25519
```

在终端里跑一下，会得到签名：

```
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAA...很长很长的一串...
-----END SSH SIGNATURE-----
```

把公钥和签名贴回去，点验证，biu～验证成功！

<br/>

再试试自检测功能——系统会自动生成一个ed25519密钥对，然后自己给自己签名验证，检查所有功能是否正常。

```
✅ 挑战生成测试: 挑战生成和存储正常
✅ 内存存储测试: 内存存储工作正常  
✅ Ed25519密钥对生成测试: Ed25519密钥对生成、签名和验证全部成功
```

看起来一切正常！<sub>（如果不正常就是bug了）</sub>

## 原理

其实原理非常简单。就是用SSH的签名功能来做身份验证。

### 挑战-响应机制

服务器生成一个随机消息，用户用私钥签名，服务器用公钥验证。这样就能证明用户确实拥有对应的私钥，而且不会泄露私钥本身。

### SSH签名

SSH不只是用来连服务器的，它还有签名功能！OpenSSH 8.0+支持`ssh-keygen -Y sign`来签名任意文件。

具体流程是这样的——

1. 服务器生成挑战消息：`VerifySSH-时间戳-随机字符串`
2. 用户用私钥签名：`echo -n "消息" | ssh-keygen -Y sign -n 命名空间 -f 私钥文件`
3. 服务器用公钥验证：`ssh-keygen -Y verify -f 公钥文件 -I 身份 -n 命名空间 -s 签名文件`

### 自检测机制

为了确保系统正常工作，内置了完整的自检测：

- **挑战生成测试**: 验证能正常生成和存储挑战
- **内存存储测试**: 验证Map存储工作正常
- **Ed25519密钥对测试**: 自动生成密钥对并完成签名验证流程

## 使用方法

首先你需要有Node.js和OpenSSH，然后把这个仓库clone回去——

```bash
git clone 这个仓库
cd VerifySSH
npm install
npm start
```

接口是这样的——

```javascript
// 获取挑战
POST /api/challenge
// 验证签名  
POST /api/verify
// 自检测
GET /api/self-test
// 生成测试密钥对
POST /api/generate-keypair
```

如果你没有SSH密钥，可以生成一个：

```bash
ssh-keygen -t ed25519 -C "your-email@example.com"
```

## API接口

### POST /api/challenge
获取验证挑战

```json
{
  "success": true,
  "challengeId": "uuid-here",
  "message": "VerifySSH-1735459200000-abc123",
  "command": "echo -n \"消息\" | ssh-keygen -Y sign -n ssh-verify -f ~/.ssh/id_ed25519"
}
```

### POST /api/verify  
验证SSH签名

```json
{
  "challengeId": "uuid-here",
  "publicKey": "ssh-ed25519 AAAAC3NzaC1...",
  "signature": "-----BEGIN SSH SIGNATURE-----\n...\n-----END SSH SIGNATURE-----"
}
```

### GET /api/self-test
运行系统自检测，返回所有测试结果

### POST /api/generate-keypair
生成临时测试密钥对<sub>（仅供测试，别用于生产环境）</sub>

## 故障排除

**ssh-keygen命令找不到？**
- 装个OpenSSH客户端就行了
- Linux: `sudo apt install openssh-client`
- macOS: 自带的，不用装
- Windows: 装Git Bash或者用WSL

**签名验证失败？**
- 检查公钥私钥是不是一对的
- 看看签名格式对不对
- 确认命令敲对了没有

**服务器起不来？**
- 看看3000端口被占了没有
- 检查防火墙设置
- 确认Node.js版本够新

## 结束

<sub>PS: 这真的只是个demo，生产环境使用........真的能用吗？</sub>
