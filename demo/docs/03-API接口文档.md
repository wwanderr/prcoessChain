# 进程链生成系统 - API接口文档

> **文档版本**: v2.0  
> **最后更新**: 2025-12-08  
> **Base URL**: `http://localhost:8080/api/processchain`

---

## 📋 目录

1. [接口概览](#1-接口概览)
2. [公共说明](#2-公共说明)
3. [批量生成进程链（端侧）](#3-批量生成进程链端侧)
4. [合并网侧和端侧进程链](#4-合并网侧和端侧进程链)
5. [数据模型详解](#5-数据模型详解)
6. [错误码说明](#6-错误码说明)
7. [调用示例](#7-调用示例)

---

## 1. 接口概览

| 接口名称 | 方法 | 路径 | 功能描述 |
|---------|------|------|---------|
| 批量生成进程链 | POST | `/batch-generate` | 为多个IP生成端侧进程链 |
| 合并进程链 | POST | `/merge-chain` | 合并网侧和端侧进程链 |

---

## 2. 公共说明

### 2.1 请求头

```
Content-Type: application/json
Accept: application/json
```

### 2.2 响应格式

**成功响应**: HTTP 200 + JSON

```json
{
  "traceIds": [...],
  "hostAddresses": [...],
  "nodes": [...],
  "edges": [...]
}
```

**失败响应**: HTTP 200 + null

```json
null
```

### 2.3 通用字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `traceIds` | List<String> | 是 | 溯源ID列表 |
| `hostAddresses` | List<String> | 是 | 主机IP列表 |
| `nodes` | List<ProcessNode> | 是 | 节点列表 |
| `edges` | List<ProcessEdge> | 是 | 边列表 |
| `foundRootNode` | Boolean | 否 | 是否找到根节点 |
| `threatSeverity` | String | 否 | 威胁等级: HIGH/MEDIUM/LOW |

---

## 3. 批量生成进程链（端侧）

### 3.1 接口信息

- **功能**: 为多个IP生成端侧进程链，所有IP的进程链合并到一个结果中
- **方法**: POST
- **路径**: `/batch-generate`

### 3.2 请求参数

#### IpMappingRelation

```json
{
  "ipAndAssociation": {
    "192.168.1.100": true,
    "192.168.1.101": false
  },
  "alarmIps": {
    "192.168.1.100": "EVENT_001"
  },
  "logs": {
    "192.168.1.101": "LOG_001"
  }
}
```

#### 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `ipAndAssociation` | Map<String, Boolean> | 是 | IP → 是否有网端关联 |
| `alarmIps` | Map<String, String> | 否 | IP → 告警EventId（网端关联） |
| `logs` | Map<String, String> | 否 | IP → 日志ID（日志关联） |

### 3.3 请求示例

```bash
curl -X POST http://localhost:8080/api/processchain/batch-generate \
  -H "Content-Type: application/json" \
  -d '{
    "ipAndAssociation": {
      "192.168.1.100": true,
      "192.168.1.101": false
    },
    "alarmIps": {
      "192.168.1.100": "EVENT_001"
    }
  }'
```

### 3.4 响应示例

```json
{
  "traceIds": ["TRACE_001", "TRACE_002"],
  "hostAddresses": ["192.168.1.100", "192.168.1.101"],
  "threatSeverity": "HIGH",
  "foundRootNode": true,
  "nodes": [
    {
      "nodeId": "GUID_ROOT_001",
      "logType": "PROCESS",
      "opType": "create",
      "nodeThreatSeverity": "HIGH",
      "isChainNode": true,
      "hostAddress": "192.168.1.100",
      "chainNode": {
        "isRoot": true,
        "isBroken": false,
        "isAlarm": true,
        "isExtensionNode": false,
        "isNetworkAssociated": true,
        "associatedEventId": "EVENT_001",
        "processEntity": {
          "processName": "cmd.exe",
          "image": "C:\\Windows\\System32\\cmd.exe",
          "commandLine": "cmd.exe /c whoami",
          "user": "Administrator",
          "startTime": "2024-01-15 10:00:00"
        }
      }
    },
    {
      "nodeId": "FILE_001",
      "logType": "FILE",
      "opType": "create",
      "isChainNode": true,
      "hostAddress": "192.168.1.100",
      "chainNode": {
        "isRoot": false,
        "isAlarm": false,
        "entity": {
          "targetFilename": "malware.exe",
          "eventType": "fileCreate",
          "md5": "abc123..."
        }
      }
    }
  ],
  "edges": [
    {
      "source": "GUID_ROOT_001",
      "target": "FILE_001",
      "val": "文件创建"
    }
  ]
}
```

### 3.5 业务规则

1. **告警选举**: 
   - 网端关联优先（`alarmIps`中的EventId）
   - 威胁等级优先（高 > 中 > 低）
   - 数量多的优先

2. **进程链构建**:
   - 高危告警: 双向遍历（包含子进程）
   - 中低危告警: 向上遍历（只追溯到根）

3. **断链处理**:
   - 如果找不到根节点，创建EXPLORE虚拟根节点
   - 所有断链节点连接到EXPLORE

4. **裁剪**:
   - 节点数 > 100 → 强制裁剪到30个
   - 保留网端关联节点和关键路径

5. **实体提取**:
   - 从裁剪后的进程提取实体（延迟拆分）
   - 每个traceId最多保留10个实体

---

## 4. 合并网侧和端侧进程链

### 4.1 接口信息

- **功能**: 将网络侧攻击路径与端点侧进程链合并
- **方法**: POST
- **路径**: `/merge-chain`

### 4.2 请求参数

#### MergeChainRequest

```json
{
  "networkNodes": [...],
  "networkEdges": [...],
  "ipMappingRelation": {
    "ipAndAssociation": {...},
    "alarmIps": {...}
  }
}
```

#### 字段说明

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `networkNodes` | List<ProcessNode> | 否 | 网侧节点列表 |
| `networkEdges` | List<ProcessEdge> | 否 | 网侧边列表 |
| `ipMappingRelation` | IpMappingRelation | 是 | IP映射关系 |

### 4.3 请求示例

```bash
curl -X POST http://localhost:8080/api/processchain/merge-chain \
  -H "Content-Type: application/json" \
  -d '{
    "networkNodes": [
      {
        "nodeId": "ATTACKER",
        "logType": "NETWORK",
        "hostAddress": "10.0.0.1",
        "nodeColor": {
          "role": "attacker",
          "color": "#FF6B6B"
        }
      },
      {
        "nodeId": "VICTIM",
        "logType": "NETWORK",
        "hostAddress": "192.168.1.100",
        "nodeColor": {
          "role": "victim",
          "color": "#4ECDC4"
        }
      }
    ],
    "networkEdges": [
      {
        "source": "ATTACKER",
        "target": "VICTIM",
        "val": "网络攻击"
      }
    ],
    "ipMappingRelation": {
      "ipAndAssociation": {
        "192.168.1.100": true
      },
      "alarmIps": {
        "192.168.1.100": "EVENT_001"
      }
    }
  }'
```

### 4.4 响应示例

```json
{
  "traceIds": ["TRACE_001"],
  "hostAddresses": ["192.168.1.100"],
  "nodes": [
    {
      "nodeId": "ATTACKER",
      "logType": "NETWORK",
      "hostAddress": "10.0.0.1",
      "nodeColor": {
        "role": "attacker",
        "color": "#FF6B6B"
      }
    },
    {
      "nodeId": "VICTIM",
      "logType": "NETWORK",
      "hostAddress": "192.168.1.100",
      "nodeColor": {
        "role": "victim",
        "color": "#4ECDC4"
      }
    },
    {
      "nodeId": "GUID_ROOT_001",
      "logType": "PROCESS",
      "hostAddress": "192.168.1.100",
      "chainNode": {
        "isRoot": true,
        "isNetworkAssociated": true,
        "processEntity": {...}
      }
    }
  ],
  "edges": [
    {
      "source": "ATTACKER",
      "target": "VICTIM",
      "val": "网络攻击"
    },
    {
      "source": "VICTIM",
      "target": "GUID_ROOT_001",
      "val": "网端桥接"
    }
  ]
}
```

### 4.5 桥接规则

1. **识别victim节点**: 网侧最后一个节点，IP匹配端侧主机
2. **识别root节点**: 端侧第一个节点（`isRoot=true`）
3. **创建桥接边**: `victim → root`
4. **角色修正**: 自动修正反向链的节点角色

---

## 5. 数据模型详解

### 5.1 ProcessNode

**进程节点/实体节点**

```json
{
  "nodeId": "GUID_001",
  "logType": "PROCESS",
  "opType": "create",
  "nodeThreatSeverity": "HIGH",
  "isChainNode": true,
  "hostAddress": "192.168.1.100",
  "nodeColor": {
    "role": "victim",
    "color": "#4ECDC4"
  },
  "chainNode": {...}
}
```

#### 字段说明

| 字段 | 类型 | 说明 | 可选值 |
|------|------|------|--------|
| `nodeId` | String | 节点唯一ID | - |
| `logType` | String | 节点类型 | PROCESS, FILE, NETWORK, DOMAIN, REGISTRY |
| `opType` | String | 操作类型 | create, modify, delete, connect, query, etc. |
| `nodeThreatSeverity` | String | 威胁等级 | HIGH, MEDIUM, LOW |
| `isChainNode` | Boolean | 是否是链节点 | true (固定) |
| `hostAddress` | String | 主机IP | - |
| `nodeColor` | NodeColor | 节点颜色和角色 | 见NodeColor |
| `chainNode` | ChainNode | 链节点信息 | 见ChainNode |

### 5.2 ChainNode

**链节点信息**

```json
{
  "isRoot": true,
  "isBroken": false,
  "isAlarm": true,
  "isExtensionNode": false,
  "extensionDepth": null,
  "isNetworkAssociated": true,
  "associatedEventId": "EVENT_001",
  "processEntity": {...},
  "entity": null
}
```

#### 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `isRoot` | Boolean | 是否是根节点 |
| `isBroken` | Boolean | 是否是断链节点 |
| `isAlarm` | Boolean | 是否是告警节点 |
| `isExtensionNode` | Boolean | 是否是扩展节点 |
| `extensionDepth` | Integer | 扩展深度（1或2） |
| `isNetworkAssociated` | Boolean | 是否是网端关联节点 |
| `associatedEventId` | String | 关联的EventId |
| `processEntity` | ProcessEntity | 进程实体（进程节点） |
| `entity` | Object | 其他实体（文件/域名/网络/注册表） |

**注意**: `processEntity` 和 `entity` 二选一，不会同时存在

### 5.3 ProcessEntity

**进程实体**

```json
{
  "processName": "cmd.exe",
  "image": "C:\\Windows\\System32\\cmd.exe",
  "commandLine": "cmd.exe /c whoami",
  "user": "Administrator",
  "md5": "abc123...",
  "sha256": "def456...",
  "startTime": "2024-01-15 10:00:00"
}
```

### 5.4 FileEntity

**文件实体**

```json
{
  "targetFilename": "malware.exe",
  "eventType": "fileCreate",
  "md5": "abc123...",
  "sha256": "def456..."
}
```

### 5.5 NetworkEntity

**网络实体**

```json
{
  "destinationIp": "8.8.8.8",
  "destinationPort": "443",
  "protocol": "TCP",
  "eventType": "networkConnect"
}
```

### 5.6 DomainEntity

**域名实体**

```json
{
  "queryName": "evil.com",
  "eventType": "dnsQuery"
}
```

### 5.7 ProcessEdge

**边**

```json
{
  "source": "GUID_PARENT",
  "target": "GUID_CHILD",
  "val": "进程创建"
}
```

#### 字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `source` | String | 源节点ID |
| `target` | String | 目标节点ID |
| `val` | String | 边类型/描述 |

#### 常见边类型

| val值 | 说明 |
|-------|------|
| `进程创建` | 父进程创建子进程 |
| `文件创建` | 进程创建文件 |
| `文件修改` | 进程修改文件 |
| `文件删除` | 进程删除文件 |
| `网络连接` | 进程发起网络连接 |
| `域名查询` | 进程查询域名 |
| `注册表操作` | 进程操作注册表 |
| `网端桥接` | 网侧连接端侧 |

### 5.8 NodeColor

**节点颜色和角色**

```json
{
  "role": "victim",
  "color": "#4ECDC4"
}
```

#### 角色和颜色

| role | color | 说明 |
|------|-------|------|
| `attacker` | `#FF6B6B` | 攻击者（红色） |
| `victim` | `#4ECDC4` | 受害者（蓝色） |
| `relay` | `#FFE66D` | 中继/跳板（黄色） |

---

## 6. 错误码说明

### 6.1 成功响应

**HTTP 200 + 非null JSON**

表示请求成功，返回进程链数据。

### 6.2 失败响应

**HTTP 200 + null**

表示请求失败，可能的原因：

| 场景 | 日志关键字 | 排查方法 |
|------|-----------|---------|
| IP列表为空 | `【输入验证失败】-> IP列表为空` | 检查 `ipAndAssociation` 是否为空 |
| ES查询失败 | `【ES查询】-> 查询失败` | 检查ES服务是否正常 |
| 无告警数据 | `【进程链生成】-> IP [xxx] 无告警数据` | 检查ES中是否有该IP的告警 |
| 告警选举失败 | `【告警选举】-> 选举失败` | 检查告警数据格式是否正确 |
| 日志查询失败 | `【日志查询】-> 查询失败` | 检查ES中是否有对应的日志 |

### 6.3 调试方法

1. **查看控制台日志**: 搜索关键字 `【进程链生成】`
2. **检查请求参数**: 确保 `ipAndAssociation` 不为空
3. **验证ES连接**: 访问 `http://localhost:9200`
4. **检查数据**: 确认ES中有对应IP的告警和日志

---

## 7. 调用示例

### 7.1 Python示例

```python
import requests
import json

# 批量生成进程链
url = "http://localhost:8080/api/processchain/batch-generate"

payload = {
    "ipAndAssociation": {
        "192.168.1.100": True,
        "192.168.1.101": False
    },
    "alarmIps": {
        "192.168.1.100": "EVENT_001"
    }
}

headers = {
    "Content-Type": "application/json"
}

response = requests.post(url, headers=headers, data=json.dumps(payload))

if response.status_code == 200:
    result = response.json()
    if result:
        print(f"成功! 节点数: {len(result['nodes'])}, 边数: {len(result['edges'])}")
        print(f"traceIds: {result['traceIds']}")
    else:
        print("失败: 返回null")
else:
    print(f"HTTP错误: {response.status_code}")
```

### 7.2 Java示例

```java
// 使用 RestTemplate
RestTemplate restTemplate = new RestTemplate();
String url = "http://localhost:8080/api/processchain/batch-generate";

// 构造请求
IpMappingRelation request = new IpMappingRelation();
Map<String, Boolean> ipAndAssociation = new HashMap<>();
ipAndAssociation.put("192.168.1.100", true);
ipAndAssociation.put("192.168.1.101", false);
request.setIpAndAssociation(ipAndAssociation);

Map<String, String> alarmIps = new HashMap<>();
alarmIps.put("192.168.1.100", "EVENT_001");
request.setAlarmIps(alarmIps);

// 发送请求
IncidentProcessChain result = restTemplate.postForObject(
    url, 
    request, 
    IncidentProcessChain.class
);

if (result != null) {
    System.out.println("成功! 节点数: " + result.getNodes().size());
    System.out.println("边数: " + result.getEdges().size());
} else {
    System.out.println("失败: 返回null");
}
```

### 7.3 JavaScript示例

```javascript
// 使用 fetch API
const url = 'http://localhost:8080/api/processchain/batch-generate';

const payload = {
  ipAndAssociation: {
    '192.168.1.100': true,
    '192.168.1.101': false
  },
  alarmIps: {
    '192.168.1.100': 'EVENT_001'
  }
};

fetch(url, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(payload)
})
  .then(response => response.json())
  .then(result => {
    if (result) {
      console.log(`成功! 节点数: ${result.nodes.length}, 边数: ${result.edges.length}`);
      console.log(`traceIds: ${result.traceIds}`);
    } else {
      console.log('失败: 返回null');
    }
  })
  .catch(error => {
    console.error('错误:', error);
  });
```

---

## 📚 相关文档

- **[00-项目总览与快速上手](./00-项目总览与快速上手.md)** - 了解项目概况
- **[01-核心架构与数据流程](./01-核心架构与数据流程.md)** - 理解系统架构
- **[04-开发与调试指南](./04-开发与调试指南.md)** - 学习开发和调试技巧

---

**最后更新**: 2025-12-08  
**文档维护者**: 开发团队

