# IncidentProcessChain 数据结构说明

本文档详细说明了进程链返回的数据结构，包括所有字段的类型和说明。

---

## 📋 目录

1. [IncidentProcessChain - 根结构](#1-incidentprocesschain---根结构)
2. [ProcessNode - 节点](#2-processnode---节点)
3. [ProcessEdge - 边](#3-processedge---边)
4. [ChainNode - 进程链节点详情](#4-chainnode---进程链节点详情)
5. [StoryNode - 故事线节点详情](#5-storynode---故事线节点详情)
6. [实体类](#6-实体类)
   - [ProcessEntity - 进程实体](#61-processentity---进程实体)
   - [AlarmNodeInfo - 告警信息](#62-alarmnodeinfo---告警信息)
   - [FileEntity - 文件实体](#63-fileentity---文件实体)
   - [NetworkEntity - 网络实体](#64-networkentity---网络实体)
   - [DomainEntity - 域名实体](#65-domainentity---域名实体)
   - [RegistryEntity - 注册表实体](#66-registryentity---注册表实体)
7. [枚举类型](#7-枚举类型)
8. [完整示例](#8-完整示例)

---

## 1. IncidentProcessChain - 根结构

**描述**: 事件进程链的根数据结构，包含所有节点和边的信息。

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `traceIds` | `List<String>` | 追踪ID列表，支持多个traceId |
| `hostAddresses` | `List<String>` | 主机IP地址列表，支持多个IP |
| `nodes` | `List<ProcessNode>` | 节点列表（包含端侧和网侧节点） |
| `edges` | `List<ProcessEdge>` | 边列表（描述节点之间的关系） |
| `threatSeverity` | `ThreatSeverity` | 整体威胁等级（HIGH/MEDIUM/LOW/UNKNOWN） |

**示例**:
```json
{
  "traceIds": ["TRACE_001", "TRACE_002"],
  "hostAddresses": ["10.50.86.171", "10.50.86.52"],
  "nodes": [...],
  "edges": [...],
  "threatSeverity": "HIGH"
}
```

---

## 2. ProcessNode - 节点

**描述**: 进程链中的节点，可以是进程链节点（ChainNode）或故事线节点（StoryNode）。

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `nodeId` | `String` | 节点唯一标识（进程GUID或IP地址） |
| `logType` | `NodeType` | 节点类型（PROCESS/FILE/NETWORK/DOMAIN/REGISTRY/EXPLORE/UNKNOWN） |
| `nodeThreatSeverity` | `ThreatSeverity` | 节点威胁等级 |
| `isChainNode` | `Boolean` | 是否为进程链节点（true=ChainNode, false=StoryNode） |
| `chainNode` | `ChainNode` | 进程链节点详情（当isChainNode=true时有值） |
| `storyNode` | `StoryNode` | 故事线节点详情（当isChainNode=false时有值） |
| `childrenCount` | `Integer` | 子节点数量（该节点下挂的直接子节点个数） |

**示例 - 进程链节点**:
```json
{
  "nodeId": "ROOT_001",
  "logType": "PROCESS",
  "nodeThreatSeverity": "HIGH",
  "isChainNode": true,
  "chainNode": { ... },
  "storyNode": null,
  "childrenCount": 3
}
```

**示例 - 故事线节点**:
```json
{
  "nodeId": "10.50.86.35",
  "logType": "UNKNOWN",
  "nodeThreatSeverity": "HIGH",
  "isChainNode": false,
  "chainNode": null,
  "storyNode": {
    "type": "attacker",
    "node": {
      "ip": "10.50.86.35",
      "isTopNode": true
    }
  },
  "childrenCount": 2
}
```

---

## 3. ProcessEdge - 边

**描述**: 描述两个节点之间的父子关系或攻击关系。

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `source` | `String` | 源节点ID（父节点或攻击源） |
| `target` | `String` | 目标节点ID（子节点或攻击目标） |
| `val` | `String` | 边的描述信息（可选） |

**示例**:
```json
{
  "source": "PARENT_001",
  "target": "CHILD_001",
  "val": ""
}
```

---

## 4. ChainNode - 进程链节点详情

**描述**: 端侧进程链节点的详细信息。

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `isRoot` | `Boolean` | 是否为根节点 |
| `isBroken` | `Boolean` | 是否为断链节点 |
| `isAlarm` | `Boolean` | 是否包含告警 |
| `alarmNodeInfo` | `AlarmNodeInfo` | 告警信息（当isAlarm=true时有值） |
| `processEntity` | `ProcessEntity` | 进程实体信息 |
| `entity` | `Object` | 其他实体（FileEntity/NetworkEntity/DomainEntity/RegistryEntity） |
| `isExtensionNode` | `Boolean` | 是否为扩展节点（向上扩展的父节点） |
| `extensionDepth` | `Integer` | 扩展深度（0=原根节点, 1=父节点, 2=祖父节点） |

**示例**:
```json
{
  "isRoot": false,
  "isBroken": false,
  "isAlarm": true,
  "alarmNodeInfo": {
    "alarmName": "恶意进程执行",
    "threatSeverity": "HIGH",
    "dvcAction": "blocked"
  },
  "processEntity": {
    "processName": "cmd.exe",
    "image": "C:\\Windows\\System32\\cmd.exe",
    "commandline": "cmd.exe /c whoami"
  },
  "entity": null,
  "isExtensionNode": false,
  "extensionDepth": 0
}
```

---

## 5. StoryNode - 故事线节点详情

**描述**: 网侧故事线节点的详细信息。

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `type` | `String` | 节点类型（attacker/victim/server） |
| `node` | `Map<String, Object>` | 其他属性（ip, port, name等动态字段） |

**示例 - Attacker 节点**:
```json
{
  "type": "attacker",
  "node": {
    "ip": "10.50.86.35",
    "isTopNode": true
  }
}
```

**示例 - Victim 节点**:
```json
{
  "type": "victim",
  "node": {
    "ip": "10.50.86.171",
    "port": "22",
    "isEdr": true,
    "associated": true
  }
}
```

---

## 6. 实体类

### 6.1 ProcessEntity - 进程实体

**描述**: 进程的详细信息。

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `opType` | `String` | 操作类型 |
| `localtime` | `String` | 本地时间 |
| `processId` | `String` | 进程ID |
| `processGuid` | `String` | 进程GUID |
| `parentProcessGuid` | `String` | 父进程GUID |
| `image` | `String` | 进程镜像路径 |
| `commandline` | `String` | 命令行参数 |
| `processUserName` | `String` | 进程用户名 |
| `processName` | `String` | 进程名称 |

**示例**:
```json
{
  "opType": "create",
  "localtime": "2025-10-31 10:00:00",
  "processId": "1234",
  "processGuid": "PROC_001",
  "parentProcessGuid": "PROC_PARENT",
  "image": "C:\\Windows\\System32\\cmd.exe",
  "commandline": "cmd.exe /c whoami",
  "processUserName": "Administrator",
  "processName": "cmd.exe"
}
```

---

### 6.2 AlarmNodeInfo - 告警信息

**描述**: 节点关联的告警信息。

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `alarmName` | `String` | 告警名称 |
| `dvcAction` | `String` | 设备处置动作 |
| `alarmDescription` | `String` | 告警描述 |
| `alarmSource` | `String` | 告警来源 |
| `threatSeverity` | `ThreatSeverity` | 威胁等级 |
| `alarmResults` | `String` | 告警结果 |

**示例**:
```json
{
  "alarmName": "恶意进程执行",
  "dvcAction": "blocked",
  "alarmDescription": "检测到可疑进程执行",
  "alarmSource": "EDR",
  "threatSeverity": "HIGH",
  "alarmResults": "已阻止"
}
```

---

### 6.3 FileEntity - 文件实体

**描述**: 文件操作的详细信息。

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `filePath` | `String` | 文件路径 |
| `targetFilename` | `String` | 目标文件名 |
| `fileSize` | `Long` | 文件大小（字节） |
| `fileMd5` | `String` | 文件MD5哈希 |
| `fileType` | `String` | 文件类型 |
| `fileName` | `String` | 文件名 |

**示例**:
```json
{
  "filePath": "C:\\temp\\malware.exe",
  "targetFilename": "malware.exe",
  "fileSize": 102400,
  "fileMd5": "d41d8cd98f00b204e9800998ecf8427e",
  "fileType": "exe",
  "fileName": "malware.exe"
}
```

---

### 6.4 NetworkEntity - 网络实体

**描述**: 网络连接的详细信息。

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `transProtocol` | `String` | 传输协议（TCP/UDP） |
| `srcAddress` | `String` | 源IP地址 |
| `srcPort` | `Integer` | 源端口 |
| `destAddress` | `String` | 目标IP地址 |
| `destPort` | `Integer` | 目标端口 |
| `initiated` | `Boolean` | 是否为主动连接 |

**示例**:
```json
{
  "transProtocol": "TCP",
  "srcAddress": "10.50.86.171",
  "srcPort": 52341,
  "destAddress": "8.8.8.8",
  "destPort": 443,
  "initiated": true
}
```

---

### 6.5 DomainEntity - 域名实体

**描述**: 域名查询的详细信息。

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `requestDomain` | `String` | 请求的域名 |
| `queryResults` | `String` | 查询结果（解析到的IP） |

**示例**:
```json
{
  "requestDomain": "malicious.com",
  "queryResults": "1.2.3.4"
}
```

---

### 6.6 RegistryEntity - 注册表实体

**描述**: 注册表操作的详细信息。

| 字段名 | 类型 | 说明 |
|--------|------|------|
| `targetObject` | `String` | 目标注册表路径 |
| `regValue` | `String` | 注册表值 |

**示例**:
```json
{
  "targetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
  "regValue": "C:\\temp\\malware.exe"
}
```

---

## 7. 枚举类型

### 7.1 NodeType - 节点类型

| 枚举值 | 说明 |
|--------|------|
| `PROCESS` | 进程节点 |
| `FILE` | 文件节点 |
| `NETWORK` | 网络节点 |
| `DOMAIN` | 域名节点 |
| `REGISTRY` | 注册表节点 |
| `EXPLORE` | 探索节点（断链占位） |
| `UNKNOWN` | 未知类型 |

### 7.2 ThreatSeverity - 威胁等级

| 枚举值 | 说明 |
|--------|------|
| `HIGH` | 高危 |
| `MEDIUM` | 中危 |
| `LOW` | 低危 |
| `UNKNOWN` | 未知 |

---

## 8. 完整示例

### 8.1 端侧进程链示例（包含扩展节点）

```json
{
  "traceIds": ["TRACE_001"],
  "hostAddresses": ["10.50.86.171"],
  "threatSeverity": "HIGH",
  "nodes": [
    {
      "nodeId": "GRANDPARENT_001",
      "logType": "PROCESS",
      "nodeThreatSeverity": "LOW",
      "isChainNode": true,
      "childrenCount": 1,
      "chainNode": {
        "isRoot": true,
        "isBroken": false,
        "isAlarm": false,
        "isExtensionNode": true,
        "extensionDepth": 2,
        "alarmNodeInfo": null,
        "processEntity": {
          "processName": "explorer.exe",
          "image": "C:\\Windows\\explorer.exe",
          "commandline": "C:\\Windows\\explorer.exe",
          "processGuid": "GRANDPARENT_001",
          "parentProcessGuid": null,
          "localtime": "2025-10-31 09:58:00"
        },
        "entity": null
      },
      "storyNode": null
    },
    {
      "nodeId": "PARENT_001",
      "logType": "PROCESS",
      "nodeThreatSeverity": "LOW",
      "isChainNode": true,
      "childrenCount": 1,
      "chainNode": {
        "isRoot": false,
        "isBroken": false,
        "isAlarm": false,
        "isExtensionNode": true,
        "extensionDepth": 1,
        "alarmNodeInfo": null,
        "processEntity": {
          "processName": "powershell.exe",
          "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "commandline": "powershell.exe",
          "processGuid": "PARENT_001",
          "parentProcessGuid": "GRANDPARENT_001",
          "localtime": "2025-10-31 09:59:00"
        },
        "entity": null
      },
      "storyNode": null
    },
    {
      "nodeId": "ROOT_001",
      "logType": "PROCESS",
      "nodeThreatSeverity": "HIGH",
      "isChainNode": true,
      "childrenCount": 3,
      "chainNode": {
        "isRoot": false,
        "isBroken": false,
        "isAlarm": true,
        "isExtensionNode": false,
        "extensionDepth": 0,
        "alarmNodeInfo": {
          "alarmName": "恶意进程执行",
          "dvcAction": "blocked",
          "alarmDescription": "检测到可疑命令执行",
          "alarmSource": "EDR",
          "threatSeverity": "HIGH",
          "alarmResults": "已阻止"
        },
        "processEntity": {
          "processName": "cmd.exe",
          "image": "C:\\Windows\\System32\\cmd.exe",
          "commandline": "cmd.exe /c whoami",
          "processGuid": "ROOT_001",
          "parentProcessGuid": "PARENT_001",
          "processId": "1234",
          "localtime": "2025-10-31 10:00:00"
        },
        "entity": null
      },
      "storyNode": null
    },
    {
      "nodeId": "CHILD_001",
      "logType": "FILE",
      "nodeThreatSeverity": "MEDIUM",
      "isChainNode": true,
      "childrenCount": 0,
      "chainNode": {
        "isRoot": false,
        "isBroken": false,
        "isAlarm": false,
        "isExtensionNode": false,
        "alarmNodeInfo": null,
        "processEntity": {
          "processName": "cmd.exe",
          "processGuid": "ROOT_001",
          "parentProcessGuid": "PARENT_001"
        },
        "entity": {
          "filePath": "C:\\temp\\malware.exe",
          "targetFilename": "malware.exe",
          "fileSize": 102400,
          "fileMd5": "d41d8cd98f00b204e9800998ecf8427e",
          "fileType": "exe",
          "fileName": "malware.exe"
        }
      },
      "storyNode": null
    },
    {
      "nodeId": "CHILD_002",
      "logType": "NETWORK",
      "nodeThreatSeverity": "HIGH",
      "isChainNode": true,
      "childrenCount": 0,
      "chainNode": {
        "isRoot": false,
        "isBroken": false,
        "isAlarm": false,
        "isExtensionNode": false,
        "alarmNodeInfo": null,
        "processEntity": {
          "processName": "cmd.exe",
          "processGuid": "ROOT_001"
        },
        "entity": {
          "transProtocol": "TCP",
          "srcAddress": "10.50.86.171",
          "srcPort": 52341,
          "destAddress": "8.8.8.8",
          "destPort": 443,
          "initiated": true
        }
      },
      "storyNode": null
    },
    {
      "nodeId": "CHILD_003",
      "logType": "REGISTRY",
      "nodeThreatSeverity": "MEDIUM",
      "isChainNode": true,
      "childrenCount": 0,
      "chainNode": {
        "isRoot": false,
        "isBroken": false,
        "isAlarm": false,
        "isExtensionNode": false,
        "alarmNodeInfo": null,
        "processEntity": {
          "processName": "cmd.exe",
          "processGuid": "ROOT_001"
        },
        "entity": {
          "targetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
          "regValue": "C:\\temp\\malware.exe"
        }
      },
      "storyNode": null
    }
  ],
  "edges": [
    {
      "source": "GRANDPARENT_001",
      "target": "PARENT_001",
      "val": ""
    },
    {
      "source": "PARENT_001",
      "target": "ROOT_001",
      "val": ""
    },
    {
      "source": "ROOT_001",
      "target": "CHILD_001",
      "val": ""
    },
    {
      "source": "ROOT_001",
      "target": "CHILD_002",
      "val": ""
    },
    {
      "source": "ROOT_001",
      "target": "CHILD_003",
      "val": ""
    }
  ]
}
```

### 8.2 网端合并示例（包含网侧和桥接）

```json
{
  "traceIds": ["TRACE_001"],
  "hostAddresses": ["10.50.86.171"],
  "threatSeverity": "HIGH",
  "nodes": [
    {
      "nodeId": "10.50.86.35",
      "logType": "UNKNOWN",
      "nodeThreatSeverity": "HIGH",
      "isChainNode": false,
      "childrenCount": 2,
      "chainNode": null,
      "storyNode": {
        "type": "attacker",
        "node": {
          "ip": "10.50.86.35",
          "isTopNode": true
        }
      }
    },
    {
      "nodeId": "10.50.86.171",
      "logType": "UNKNOWN",
      "nodeThreatSeverity": "HIGH",
      "isChainNode": false,
      "childrenCount": 1,
      "chainNode": null,
      "storyNode": {
        "type": "victim",
        "node": {
          "ip": "10.50.86.171",
          "port": "22",
          "isEdr": true,
          "associated": true
        }
      }
    },
    {
      "nodeId": "10.50.86.52",
      "logType": "UNKNOWN",
      "nodeThreatSeverity": "MEDIUM",
      "isChainNode": false,
      "childrenCount": 0,
      "chainNode": null,
      "storyNode": {
        "type": "victim",
        "node": {
          "ip": "10.50.86.52",
          "port": "32",
          "isEdr": false,
          "associated": false
        }
      }
    },
    {
      "nodeId": "ROOT_171",
      "logType": "PROCESS",
      "nodeThreatSeverity": "HIGH",
      "isChainNode": true,
      "childrenCount": 2,
      "chainNode": {
        "isRoot": true,
        "isBroken": false,
        "isAlarm": true,
        "isExtensionNode": false,
        "alarmNodeInfo": {
          "alarmName": "SSH暴力破解",
          "threatSeverity": "HIGH"
        },
        "processEntity": {
          "processName": "sshd",
          "image": "/usr/sbin/sshd",
          "commandline": "sshd -D",
          "processGuid": "ROOT_171"
        },
        "entity": null
      },
      "storyNode": null
    },
    {
      "nodeId": "CHILD_171_1",
      "logType": "PROCESS",
      "nodeThreatSeverity": "MEDIUM",
      "isChainNode": true,
      "childrenCount": 0,
      "chainNode": {
        "isRoot": false,
        "isBroken": false,
        "isAlarm": false,
        "processEntity": {
          "processName": "bash",
          "image": "/bin/bash",
          "processGuid": "CHILD_171_1",
          "parentProcessGuid": "ROOT_171"
        },
        "entity": null
      },
      "storyNode": null
    },
    {
      "nodeId": "CHILD_171_2",
      "logType": "NETWORK",
      "nodeThreatSeverity": "HIGH",
      "isChainNode": true,
      "childrenCount": 0,
      "chainNode": {
        "isRoot": false,
        "isBroken": false,
        "isAlarm": false,
        "processEntity": {
          "processName": "sshd",
          "processGuid": "ROOT_171"
        },
        "entity": {
          "transProtocol": "TCP",
          "srcAddress": "10.50.86.171",
          "srcPort": 22,
          "destAddress": "10.50.86.35",
          "destPort": 52341,
          "initiated": false
        }
      },
      "storyNode": null
    }
  ],
  "edges": [
    {
      "source": "10.50.86.35",
      "target": "10.50.86.171",
      "val": "SSH攻击"
    },
    {
      "source": "10.50.86.35",
      "target": "10.50.86.52",
      "val": "横向移动"
    },
    {
      "source": "10.50.86.171",
      "target": "ROOT_171",
      "val": ""
    },
    {
      "source": "ROOT_171",
      "target": "CHILD_171_1",
      "val": ""
    },
    {
      "source": "ROOT_171",
      "target": "CHILD_171_2",
      "val": ""
    }
  ]
}
```

---

## 9. 数据流程图

```
IncidentProcessChain (根结构)
├── traceIds: ["TRACE_001"]
├── hostAddresses: ["10.50.86.171"]
├── threatSeverity: "HIGH"
├── nodes: [
│   ├── ProcessNode (网侧节点 - Attacker)
│   │   ├── nodeId: "10.50.86.35"
│   │   ├── isChainNode: false
│   │   ├── childrenCount: 2
│   │   └── storyNode: { type: "attacker", ... }
│   │
│   ├── ProcessNode (网侧节点 - Victim)
│   │   ├── nodeId: "10.50.86.171"
│   │   ├── isChainNode: false
│   │   ├── childrenCount: 1
│   │   └── storyNode: { type: "victim", ... }
│   │
│   ├── ProcessNode (端侧节点 - Root)
│   │   ├── nodeId: "ROOT_171"
│   │   ├── isChainNode: true
│   │   ├── childrenCount: 2
│   │   └── chainNode: {
│   │       ├── isRoot: true
│   │       ├── isAlarm: true
│   │       ├── alarmNodeInfo: { ... }
│   │       ├── processEntity: { ... }
│   │       └── entity: null
│   │       }
│   │
│   └── ProcessNode (端侧节点 - Child)
│       ├── nodeId: "CHILD_171_1"
│       ├── isChainNode: true
│       ├── childrenCount: 0
│       └── chainNode: { ... }
│   ]
│
└── edges: [
    ├── { source: "10.50.86.35", target: "10.50.86.171" }  // 网侧边
    ├── { source: "10.50.86.171", target: "ROOT_171" }     // 桥接边
    └── { source: "ROOT_171", target: "CHILD_171_1" }      // 端侧边
    ]
```

---

## 10. 使用说明

### 10.1 判断节点类型

```javascript
// 判断是进程链节点还是故事线节点
if (node.isChainNode) {
    // 处理进程链节点
    const chainNode = node.chainNode;
    console.log("进程名:", chainNode.processEntity.processName);
    
    // 判断是否有告警
    if (chainNode.isAlarm) {
        console.log("告警:", chainNode.alarmNodeInfo.alarmName);
    }
} else {
    // 处理故事线节点
    const storyNode = node.storyNode;
    console.log("节点类型:", storyNode.type); // attacker/victim/server
    console.log("IP:", storyNode.node.ip);
}
```

### 10.2 遍历子节点

```javascript
// 使用 childrenCount 判断是否有子节点
if (node.childrenCount > 0) {
    console.log(`节点 ${node.nodeId} 有 ${node.childrenCount} 个子节点`);
    
    // 通过 edges 找到子节点
    const children = edges
        .filter(edge => edge.source === node.nodeId)
        .map(edge => nodes.find(n => n.nodeId === edge.target));
}
```

### 10.3 构建树形结构

```javascript
function buildTree(nodes, edges, rootId) {
    const root = nodes.find(n => n.nodeId === rootId);
    if (!root) return null;
    
    // 递归构建子节点
    root.children = edges
        .filter(e => e.source === rootId)
        .map(e => buildTree(nodes, edges, e.target));
    
    return root;
}
```

---

## 11. 注意事项

1. **节点类型判断**: 使用 `isChainNode` 字段区分进程链节点和故事线节点
2. **子节点统计**: `childrenCount` 字段已自动计算，包含所有类型的边（端侧、网侧、扩展、桥接）
3. **扩展节点**: 通过 `isExtensionNode` 和 `extensionDepth` 识别向上扩展的父节点
4. **断链节点**: 通过 `isBroken` 识别父节点缺失的断链节点
5. **实体类型**: `entity` 字段的实际类型取决于 `logType`（FILE→FileEntity, NETWORK→NetworkEntity等）
6. **枚举值**: 所有枚举类型（NodeType, ThreatSeverity）在JSON中序列化为字符串

---

**文档版本**: v1.0  
**最后更新**: 2025-10-31  
**维护者**: Process Chain Team-wcs



