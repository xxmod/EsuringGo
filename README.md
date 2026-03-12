# EsuringGo

中国电信天翼校园网（ESurfing）自动认证拨号客户端的 Go 语言实现。

## 功能

- 自动检测强制门户（Captive Portal）并完成认证
- 支持 9 种加密算法（AES-CBC/ECB、3DES-CBC/ECB、SM4-CBC/ECB、ModXTEA、ModXTEA-XTEAIV、ZUC-128）
- 自动心跳保活，断线自动重连
- 支持短信验证码登录
- 跨平台编译（Windows / Linux / macOS）

## 构建

```bash
go build -o esurfing .
```

## 使用

```bash
esurfing -u <手机号> -p <密码> [-s <短信验证码>]
```

### 参数

| 参数 | 说明 |
|------|------|
| `-u` / `-user` | 登录用户名（手机号） |
| `-p` / `-password` | 登录密码 |
| `-s` / `-sms` | 预填短信验证码（可选） |

### 示例

```bash
# 基本登录
esurfing -u 13800138000 -p mypassword

# 携带短信验证码
esurfing -u 13800138000 -p mypassword -s 123456
```

程序启动后会自动检测网络状态，完成认证并保持连接。按 `Ctrl+C` 安全退出。

## 测试

```bash
go test ./... -v
```

## 项目结构

```
├── main.go              # 入口
├── client.go            # 认证客户端主逻辑
├── session.go           # 会话与加密管理
├── states.go            # 全局状态（线程安全）
├── constants.go         # 常量定义
├── cipher/              # 加密算法实现
│   ├── cipher.go        #   工厂函数
│   ├── keydata.go       #   密钥数据
│   ├── aescbc.go        #   AES-CBC
│   ├── aesecb.go        #   AES-ECB
│   ├── desedecbc.go     #   3DES-CBC
│   ├── desedeecb.go     #   3DES-ECB
│   ├── sm4cbc.go        #   SM4-CBC
│   ├── sm4ecb.go        #   SM4-ECB
│   ├── modxtea.go       #   ModXTEA
│   ├── modxteaxteaiv.go #   ModXTEA-XTEAIV
│   └── zuc.go           #   ZUC-128
├── network/             # 网络模块
│   ├── client.go        #   HTTP 客户端
│   └── connectivity.go  #   门户检测
├── utils/               # 工具函数
│   └── utils.go
└── model/               # 数据模型
    └── model.go
```

## 依赖

- [gmsm](https://github.com/emmansun/gmsm) — 国密 SM4 / ZUC 算法
- [google/uuid](https://github.com/google/uuid) — UUID 生成

## 许可证

MIT
