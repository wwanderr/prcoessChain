
## 基本信息

**TraceID(s)**: [traceId-test-001]
**主机IP(s)**: [10.50.110.193]
**威胁等级**: HIGH
**节点数量**: 7
**边数量**: 6

## 进程链结构（简洁视图）

**图例**: 🌐=网侧攻击 | 💻=端侧进程 | 📄=文件操作 | 🚨=告警节点 | ⚡=ROOT节点

```
└── 🌐 [webshell_upload] 10.50.86.151:51344 → 10.50.110.193:80 (HTTP) [HIGH]
    └── 💻 [EXTEND] svchost.exe (PID:896) - SYSTEM [LOW]
        └── 💻 [EXTEND] RuntimeBroker.exe (PID:424) - DESKTOP-M0S0L3H\Administrator [LOW]
            └── 💻 phpstudy_pro.exe (PID:6992) - DESKTOP-M0S0L3H\Administrator [MEDIUM]
                └── 💻 xp.cn_cgi.exe (PID:3040) - DESKTOP-M0S0L3H\Administrator [MEDIUM]
                    └── 🚨 [ROOT,ALARM] php-cgi.exe (PID:228) - DESKTOP-M0S0L3H\Administrator [HIGH]
                        └── 📄 [webshell_file] bello.php (Backdoor/PHP.WebShell.ek) [HIGH]
```

## 进程链结构（详细视图）

```
════════════════════════════════════════════════════════════════════════════
                            攻 击 链 完 整 视 图                              
════════════════════════════════════════════════════════════════════════════

【端侧】主机进程执行链
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                    【网侧】网络攻击桥接到端侧                       ║
    ╠═══════════════════════════════════════════════════════════════════╣
    ║ 🌐 攻击者: 10.50.86.151:51344
    ║    协议: HTTP POST
    ║    目标: 10.50.110.193:80
    ║    URL: /pika/vul/unsafeupload/clientcheck.php
    ║    检测: 检测到上传冰蝎webshell文件(PHP)
    ╚═══════════════════════════════════════════════════════════════════╝
                                 ║
                                 ▼ 桥接到端侧进程
                                 ║
    ┏────────────────────────────────────────────────────────────────────┓
    ┃ 🔗 svchost.exe (PID:896) (扩展节点)                                    ┃
    ┃────────────────────────────────────────────────────────────────────┃
    ┃  👤 用户: SYSTEM                                                  ┃
    ┃  📝 命令: C:\WINDOWS\system32\svchost.exe -k DcomLaunch -p        ┃
    ┃  🕐 时间: 2025-05-15 18:28:53                                     ┃
    ┃  🟢 威胁: LOW                                                     ┃
    ┗────────────────────────────────────────────────────────────────────┛
                                 ║
                                 ▼
                                 ║
    ┏────────────────────────────────────────────────────────────────────┓
    ┃ 🔗 RuntimeBroker.exe (PID:424) (扩展节点)                              ┃
    ┃────────────────────────────────────────────────────────────────────┃
    ┃  👤 用户: DESKTOP-M0S0L3H\Administrator                           ┃
    ┃  📝 命令: C:\Windows\System32\RuntimeBroker.exe -Embedding        ┃
    ┃  🕐 时间: 2025-05-21 07:55:33                                     ┃
    ┃  🟢 威胁: LOW                                                     ┃
    ┗────────────────────────────────────────────────────────────────────┛
                                 ║
                                 ▼
                                 ║
    ┏────────────────────────────────────────────────────────────────────┓
    ┃ 💻 phpstudy_pro.exe (PID:6992)                                     ┃
    ┃────────────────────────────────────────────────────────────────────┃
    ┃  👤 用户: DESKTOP-M0S0L3H\Administrator                           ┃
    ┃  📝 命令: "C:\phpstudy_pro\COM\phpstudy_pro.exe"                  ┃
    ┃  🕐 时间: 2025-05-21 09:48:08                                     ┃
    ┃  🟡 威胁: MEDIUM                                                  ┃
    ┗────────────────────────────────────────────────────────────────────┛
                                 ║
                                 ▼
                                 ║
    ┏────────────────────────────────────────────────────────────────────┓
    ┃ 💻 xp.cn_cgi.exe (PID:3040)                                        ┃
    ┃────────────────────────────────────────────────────────────────────┃
    ┃  👤 用户: DESKTOP-M0S0L3H\Administrator                           ┃
    ┃  📝 命令: C:\phpstudy_pro\COM\xp.cn_cgi.exe  ../Extensions/php... ┃
    ┃  🕐 时间: 2025-05-21 09:50:31                                     ┃
    ┃  🟡 威胁: MEDIUM                                                  ┃
    ┗────────────────────────────────────────────────────────────────────┛
                                 ║
                                 ▼
                                 ║
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃ 🚨 php-cgi.exe (PID:228) ⚠️ 告警节点 🎯 根节点                            ┃
    ┃────────────────────────────────────────────────────────────────────┃
    ┃  👤 用户: DESKTOP-M0S0L3H\Administrator                           ┃
    ┃  📝 命令: ../Extensions/php/php7.3.4nts/php-cgi.exe               ┃
    ┃  🕐 时间: 2025-05-21 09:50:31                                     ┃
    ┃  🔴 威胁: HIGH                                                    ┃
    ┃════════════════════════════════════════════════════════════════════┃
    ┃  🚨 告警: 发现Backdoor/PHP.WebShell.ek病毒文件创建或执行                     ┃
    ┃     类型: /Malware/Backdoor                                       ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                                 ║
                                 ▼ 创建文件
                                 ║
【端侧】恶意文件
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃ 📄 文件: bello.php
    ┃    路径: C:\phpstudy_pro\WWW\pika\vul\unsafeupload\uploads\bello.php
    ┃    病毒: Backdoor/PHP.WebShell.ek
    ┃    MD5: 723949106392537a014a6c22862d0f46
    ┃    威胁: HIGH
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

════════════════════════════════════════════════════════════════════════════
```

## 攻击摘要

**网络攻击来源**:

- 来源: 10.50.86.151:51344
- 目标: 10.50.110.193:80
- 协议: HTTP
- URL: /pika/vul/unsafeupload/clientcheck.php
- 检测规则: 检测到上传冰蝎webshell文件(PHP)

**告警事件**:

- 发现Backdoor/PHP.WebShell.ek病毒文件创建或执行
  - 类型: /Malware/Backdoor
  - 描述: 检测到PHP Webshell文件创建

## 节点详细信息

### 🌐 网络侧信息

#### 1. webshell_upload

- **节点ID**: NETWORK-001-UPLOAD
- **类型**: NETWORK
- **威胁等级**: HIGH
- **是否进程链节点**: false
- **故事线类型**: webshell_upload
- **详细信息**:
  - srcAddress: 10.50.86.151
  - srcPort: 51344
  - destAddress: 10.50.110.193
  - destPort: 80
  - protocol: HTTP
  - method: POST
  - url: /pika/vul/unsafeupload/clientcheck.php
  - ruleName: 检测到上传冰蝎webshell文件(PHP)
  - attackTime: 2025-05-23 15:31:06
- **子节点数**: 0

### 📁 文件侧信息

#### 1. webshell_file

- **节点ID**: FILE-001-WEBSHELL
- **类型**: FILE
- **威胁等级**: HIGH
- **是否进程链节点**: false
- **故事线类型**: webshell_file
- **详细信息**:
  - fileName: bello.php
  - filePath: C:\phpstudy_pro\WWW\pika\vul\unsafeupload\uploads\bello.php
  - fileMd5: 723949106392537a014a6c22862d0f46
  - virusName: Backdoor/PHP.WebShell.ek
  - virusType: Backdoor
  - opType: create
  - createTime: 2025-05-23 15:41:00
- **子节点数**: 0

### ⚙️ 进程链信息

#### 1. svchost.exe

- **节点ID**: GUID-001-SVCHOST
- **类型**: PROCESS
- **威胁等级**: LOW
- **是否进程链节点**: true
- **是否根节点**: false
- **是否告警节点**: false
- **是否断链**: false
- **进程名**: svchost.exe
- **进程ID**: 896
- **命令行**: C:\WINDOWS\system32\svchost.exe -k DcomLaunch -p
- **用户**: SYSTEM
- **启动时间**: 2025-05-15 18:28:53
- **MD5**: 3d1034d6ed3daed60816a25c561e8c83
- **子节点数**: 1

#### 2. RuntimeBroker.exe

- **节点ID**: GUID-002-RUNTIME
- **类型**: PROCESS
- **威胁等级**: LOW
- **是否进程链节点**: true
- **是否根节点**: false
- **是否告警节点**: false
- **是否断链**: false
- **进程名**: RuntimeBroker.exe
- **进程ID**: 424
- **命令行**: C:\Windows\System32\RuntimeBroker.exe -Embedding
- **用户**: DESKTOP-M0S0L3H\Administrator
- **启动时间**: 2025-05-21 07:55:33
- **MD5**: 51e04ae0701a1d33fdd89b96d7ce12a4
- **子节点数**: 1

#### 3. phpstudy_pro.exe

- **节点ID**: GUID-003-PHPSTUDY
- **类型**: PROCESS
- **威胁等级**: MEDIUM
- **是否进程链节点**: true
- **是否根节点**: false
- **是否告警节点**: false
- **是否断链**: false
- **进程名**: phpstudy_pro.exe
- **进程ID**: 6992
- **命令行**: "C:\phpstudy_pro\COM\phpstudy_pro.exe"
- **用户**: DESKTOP-M0S0L3H\Administrator
- **启动时间**: 2025-05-21 09:48:08
- **MD5**: 47f5bcae0727743d845fba7220611ae1
- **子节点数**: 1

#### 4. xp.cn_cgi.exe

- **节点ID**: GUID-004-XPCGI
- **类型**: PROCESS
- **威胁等级**: MEDIUM
- **是否进程链节点**: true
- **是否根节点**: false
- **是否告警节点**: false
- **是否断链**: false
- **进程名**: xp.cn_cgi.exe
- **进程ID**: 3040
- **命令行**: C:\phpstudy_pro\COM\xp.cn_cgi.exe  ../Extensions/php/php7.3.4nts/php-cgi.exe 9000 1+16
- **用户**: DESKTOP-M0S0L3H\Administrator
- **启动时间**: 2025-05-21 09:50:31
- **MD5**: 328873cb09b771c6c48f8609400a3e6a
- **子节点数**: 1

#### 5. php-cgi.exe

- **节点ID**: GUID-005-PHPCGI
- **类型**: PROCESS
- **威胁等级**: HIGH
- **是否进程链节点**: true
- **是否根节点**: true
- **是否告警节点**: true
- **是否断链**: false
- **进程名**: php-cgi.exe
- **进程ID**: 228
- **命令行**: ../Extensions/php/php7.3.4nts/php-cgi.exe
- **用户**: DESKTOP-M0S0L3H\Administrator
- **启动时间**: 2025-05-21 09:50:31
- **MD5**: 5caa626639f9c87c07f04a5c2fa770f4
- **告警名称**: 发现Backdoor/PHP.WebShell.ek病毒文件创建或执行
- **告警规则**: Webshell文件创建检测
- **告警类型**: /Malware/Backdoor
- **告警消息**: 检测到PHP Webshell文件创建
- **子节点数**: 1

## 边关系列表

| 源节点 | 目标节点 | 关系描述 |
|--------|----------|----------|
| svchost.exe(896) | RuntimeBroker.exe(424) | process_create |
| RuntimeBroker.exe(424) | phpstudy_pro.exe(6992) | process_create |
| NETWORK-001-UPLOAD | svchost.exe(896) | http_request |
| phpstudy_pro.exe(6992) | xp.cn_cgi.exe(3040) | process_create |
| xp.cn_cgi.exe(3040) | php-cgi.exe(228) | process_create |
| php-cgi.exe(228) | FILE-001-WEBSHELL | file_create |
