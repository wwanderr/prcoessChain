# WebShell文件上传攻击测试案例文档

## 概述

本文档描述了WebShell文件上传攻击的测试案例，包含4个不同复杂度的进程链场景，用于验证进程链生成系统的各种处理能力。

## 测试案例结构

### 案例1 - 基础案例
**IP地址**: `10.50.109.192`  
**描述**: 基础的WebShell上传攻击链，包含两个相关进程

#### 进程链关系
```
System(SYSTEM[4]) 
  └── smss.exe(SYSTEM[436])
      └── smss.exe(NT AUTHORITY\SYSTEM[10584])
          └── winlogon.exe(NT AUTHORITY\SYSTEM[8380])
              └── userinit.exe(DESKTOP-M0S0L3H\Administrator[2060])
                  └── explorer.exe(DESKTOP-M0S0L3H\Administrator[10668])
                      └── phpstudy_x64_8.1.0.7.exe(DESKTOP-M0S0L3H\Administrator[9912])
                          └── phpstudy_x64_8.1.0.7.tmp(DESKTOP-M0S0L3H\Administrator[424])
                              └── phpstudy_pro.exe(DESKTOP-M0S0L3H\Administrator[6992])
                                  └── xp.cn_cgi.exe(DESKTOP-M0S0L3H\Administrator[3040])
                                      └── php-cgi.exe(DESKTOP-M0S0L3H\Administrator[228]) [ROOT]
                                          └── php-cgi.exe(DESKTOP-M0S0L3H\Administrator[228]) [WebShell创建]
```

#### 关键信息
- **根节点**: `processGuid = "E3E5C129C46B2111"`, `traceId = "E3E5C129C46B2111"`
- **攻击类型**: Backdoor/PHP.WebShell.ek 病毒文件创建
- **文件**: `bello.php`
- **技术**: T1105 (入口工具传输)

---

### 案例2 - 长链场景
**IP地址**: `192.168.1.101`  
**描述**: 线性长链攻击，展示完整的攻击路径

#### 进程链关系
```
System(SYSTEM[4]) 
  └── ... (系统进程链)
      └── php-cgi.exe(DESKTOP-M0S0L3H\Administrator[228]) [ROOT]
          └── cmd.exe(DESKTOP-M0S0L3H\Administrator[229]) [WebShell执行]
              └── powershell.exe(DESKTOP-M0S0L3H\Administrator[230]) [后门程序]
                  └── reg.exe(DESKTOP-M0S0L3H\Administrator[231]) [持久化]
```

#### 攻击步骤
1. **WebShell上传**: `php-cgi.exe` 创建 `bello.php`
2. **命令执行**: `cmd.exe` 执行系统命令
3. **后门植入**: `powershell.exe` 执行编码命令，创建后门程序
4. **持久化**: `reg.exe` 修改注册表，实现持久化

#### 关键信息
- **根节点**: `processGuid = "E3E5C129C46B2111"`, `traceId = "E3E5C129C46B2111"`
- **链长度**: 4个攻击节点
- **技术**: T1105 → T1505.003 → T1059.001 → T1547.001

---

### 案例3 - 分支链场景
**IP地址**: `192.168.1.102`  
**描述**: 分支攻击链，一个进程启动多个子进程

#### 进程链关系
```
System(SYSTEM[4]) 
  └── ... (系统进程链)
      └── php-cgi.exe(DESKTOP-M0S0L3H\Administrator[228]) [ROOT]
          └── cmd.exe(DESKTOP-M0S0L3H\Administrator[229]) [WebShell执行]
              └── powershell.exe(DESKTOP-M0S0L3H\Administrator[230]) [后门程序]
                  ├── reg.exe(DESKTOP-M0S0L3H\Administrator[231]) [分支1: 数据窃取]
                  └── netstat.exe(DESKTOP-M0S0L3H\Administrator[232]) [分支2: 网络扫描]
```

#### 攻击步骤
1. **WebShell上传**: `php-cgi.exe` 创建 `bello.php`
2. **命令执行**: `cmd.exe` 执行系统命令
3. **后门植入**: `powershell.exe` 执行编码命令
4. **分支攻击**:
   - **分支1**: `reg.exe` 修改注册表，实现数据窃取程序持久化
   - **分支2**: `netstat.exe` 进行网络扫描，收集网络信息

#### 关键信息
- **根节点**: `processGuid = "E3E5C129C46B2111"`, `traceId = "E3E5C129C46B2111"`
- **分支数**: 2个分支
- **技术**: T1105 → T1505.003 → T1059.001 → [T1547.001, T1046]

---

### 案例4 - 断链场景
**IP地址**: `192.168.1.103`  
**描述**: 断链攻击，展示攻击链中断和重新开始

#### 进程链关系
```
System(SYSTEM[4]) 
  └── ... (系统进程链)
      └── php-cgi.exe(DESKTOP-M0S0L3H\Administrator[228]) [ROOT]
          └── cmd.exe(DESKTOP-M0S0L3H\Administrator[229]) [WebShell执行]
              └── [断链]

[独立进程链]
System(SYSTEM[4]) 
  └── ... (系统进程链)
      └── notepad.exe(DESKTOP-M0S0L3H\Administrator[233]) [独立恶意程序]
```

#### 攻击步骤
1. **WebShell上传**: `php-cgi.exe` 创建 `bello.php`
2. **命令执行**: `cmd.exe` 执行系统命令
3. **断链**: 攻击链在此中断
4. **独立攻击**: `notepad.exe` 作为独立进程执行恶意操作

#### 关键信息
- **根节点**: `processGuid = "E3E5C129C46B2111"`, `traceId = "E3E5C129C46B2111"`
- **断链点**: `cmd.exe` 后
- **独立进程**: `notepad.exe` (parentProcessId=0)
- **技术**: T1105 → T1505.003 → [断链] → T1547.001

---

## 测试数据文件说明

### 文件命名规则
- `network1.json`: 网络侧数据
- `endpoint1.json`: 端点侧数据（根节点）
- `endpoint2.json`: 端点侧数据（第二层）
- `endpoint3.json`: 端点侧数据（第三层）
- `endpoint4.json`: 端点侧数据（第四层/分支）
- `endpoint5.json`: 端点侧数据（第五层/分支）

### 关键字段说明
- `processGuid`: 进程唯一标识
- `traceId`: 追踪标识，与根节点processGuid相同
- `parentProcessGuid`: 父进程标识
- `parentProcessId`: 父进程ID
- `hostAddress`: 主机IP地址
- `processChain`: 完整进程链字符串

## 测试验证点

### 1. 基础功能验证
- [ ] 进程链正确构建
- [ ] 网端数据正确关联
- [ ] 根节点正确识别

### 2. 长链处理验证
- [ ] 线性链正确构建
- [ ] 时间顺序正确
- [ ] 父子关系正确

### 3. 分支链处理验证
- [ ] 分支节点正确识别
- [ ] 多分支正确构建
- [ ] 分支独立性保持

### 4. 断链处理验证
- [ ] 断链点正确识别
- [ ] 独立进程正确处理
- [ ] 断链前后数据分离

### 5. IP隔离验证
- [ ] 不同IP的进程链不混淆
- [ ] 同IP的进程链正确关联
- [ ] 网端IP匹配正确

## 使用说明

1. **运行测试**: 使用各个案例的JSON文件作为输入
2. **验证结果**: 检查生成的进程链是否符合预期结构
3. **性能测试**: 验证系统对不同复杂度链的处理性能
4. **边界测试**: 验证断链、分支等特殊情况的处理

## 技术细节

### 进程链构建算法
- 基于 `processGuid` 和 `parentProcessGuid` 构建父子关系
- 使用 `traceId` 识别同一攻击链的所有进程
- 通过时间戳验证进程启动顺序

### 网端关联算法
- 基于IP地址匹配网络侧和端点侧数据
- 使用时间窗口进行数据关联
- 通过安全域和机构ID进行精确匹配

### 断链检测算法
- 检测 `parentProcessId = 0` 的进程
- 识别时间间隔过大的进程
- 分析进程链的连续性

---

*文档版本: 1.0*  
*创建时间: 2025-10-29*  
*最后更新: 2025-10-29*
