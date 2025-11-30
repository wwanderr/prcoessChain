# 节点日志 opType 问题修复完成

**日期**：2025-05-26  
**问题**：
1. 拆分后的进程节点，opType 都变成了 "create"
2. domain 节点同时有 alarmNodeInfo、processEntity 和 entity

**状态**：✅ 已修复

---

## 修复内容

### 问题1：子进程节点 opType 被虚拟日志覆盖 ✅

#### 根因

虚拟父节点的日志（opType="create"）混入子节点，`getLatestLog` 可能选中虚拟日志。

#### 修复方案

**步骤1：为虚拟日志添加标记**

**文件**：`LogNodeSplitter.java` 第217行

```java
// 创建虚拟日志（使用parent字段）
RawLog parentLog = new RawLog();
// ... 其他字段设置 ...
parentLog.setLogType("process");
parentLog.setOpType("create");

// ⚠️ 重要：标记为虚拟日志，避免在日志选择时被优先选择
parentLog.setEventId("VIRTUAL_LOG_" + actualParentNodeId);
```

**步骤2：优化日志选择逻辑**

**文件**：`IncidentConverters.java` 第162-217行

```java
/**
 * 选择时间最近的日志
 * 优先选择非虚拟日志，避免虚拟父节点的日志（opType=create）覆盖真实日志
 */
private static RawLog getLatestLog(List<RawLog> logs) {
    if (logs == null || logs.isEmpty()) {
        return null;
    }
    
    // 第一步：区分虚拟日志和真实日志
    RawLog latestRealLog = null;
    RawLog latestVirtualLog = null;
    
    for (RawLog logItem : logs) {
        if (logItem == null) continue;
        
        if (isVirtualLog(logItem)) {
            // 虚拟日志
            if (latestVirtualLog == null) {
                latestVirtualLog = logItem;
            } else {
                String a = logItem.getStartTime();
                String b = latestVirtualLog.getStartTime();
                if (a != null && (b == null || a.compareTo(b) > 0)) {
                    latestVirtualLog = logItem;
                }
            }
        } else {
            // 真实日志
            if (latestRealLog == null) {
                latestRealLog = logItem;
            } else {
                String a = logItem.getStartTime();
                String b = latestRealLog.getStartTime();
                if (a != null && (b == null || a.compareTo(b) > 0)) {
                    latestRealLog = logItem;
                }
            }
        }
    }
    
    // 第二步：优先返回真实日志，没有真实日志才返回虚拟日志
    return latestRealLog != null ? latestRealLog : latestVirtualLog;
}

/**
 * 判断是否为虚拟日志
 */
private static boolean isVirtualLog(RawLog rawLog) {
    if (rawLog == null) return false;
    
    String eventId = rawLog.getEventId();
    return eventId != null && eventId.startsWith("VIRTUAL_LOG_");
}
```

#### 修复效果

**修复前**：
```json
{
  "nodeId": "CHILD_123",
  "logType": "process",
  "opType": "create",  ← 错误：被虚拟日志覆盖
  "chainNode": {
    "processEntity": {
      "opType": "create"  ← 错误
    }
  }
}
```

**修复后**：
```json
{
  "nodeId": "CHILD_123",
  "logType": "process",
  "opType": "terminate",  ← 正确：保留原始值
  "chainNode": {
    "processEntity": {
      "opType": "terminate"  ← 正确
    }
  }
}
```

**虚拟父节点**（正常）：
```json
{
  "nodeId": "PARENT_456",
  "logType": "process",
  "opType": "create",  ← 虚拟节点是 create，这是对的
  "chainNode": {
    "processEntity": {
      "opType": "create"
    }
  }
}
```

---

### 问题2：实体节点有多余字段 ✅

#### 根因

告警信息处理逻辑没有区分节点类型，所有节点都会设置 alarmNodeInfo。

#### 修复方案

**文件**：`IncidentConverters.java` 第35-120行

**修改内容**：

1. **将告警处理移到进程节点分支内**：

```java
if ("process".equals(nodeType)) {
    // ========== 进程节点：设置告警信息和进程实体 ==========
    finalNode.setLogType("process");
    finalNode.setOpType(latestLog.getOpType());
    
    // 进程节点才设置告警信息
    if (isAlarm) {
        RawAlarm latestAlarm = getLatestAlarm(alarms);
        if (latestAlarm != null) {
            AlarmNodeInfo alarmInfo = convertToAlarmNodeInfo(latestAlarm);
            chainNode.setAlarmNodeInfo(alarmInfo);
            finalNode.setNodeThreatSeverity(...);
        }
    }
    
    // 只设置 processEntity，entity 为 null
    chainNode.setProcessEntity(convertToProcessEntityForProcessNode(latestLog));
    chainNode.setEntity(null);
}
```

2. **实体节点明确不设置告警**：

```java
else if (nodeType != null && nodeType.endsWith("_entity")) {
    // ========== 实体节点：只设置实体信息 ==========
    String entityType = nodeType.replace("_entity", "");
    finalNode.setLogType(entityType);
    finalNode.setOpType(latestLog.getOpType());
    
    // 实体节点不设置告警信息
    chainNode.setAlarmNodeInfo(null);
    
    // 只设置 entity，processEntity 为 null
    chainNode.setProcessEntity(null);
    chainNode.setEntity(convertToEntity(latestLog, entityType));
}
```

3. **兜底逻辑也处理告警**：

```java
else {
    // 兜底逻辑
    finalNode.setLogType(latestLog.getLogType());
    finalNode.setOpType(latestLog.getOpType());
    
    // 兜底逻辑也可能有告警
    if (isAlarm) {
        RawAlarm latestAlarm = getLatestAlarm(alarms);
        if (latestAlarm != null) {
            AlarmNodeInfo alarmInfo = convertToAlarmNodeInfo(latestAlarm);
            chainNode.setAlarmNodeInfo(alarmInfo);
            finalNode.setNodeThreatSeverity(...);
        }
    }
    
    Object entity = convertToEntity(latestLog, latestLog.getLogType());
    chainNode.setEntity(entity);
    chainNode.setProcessEntity(convertToProcessEntity(latestLog, entity));
}
```

4. **只有告警没有日志的情况**：

```java
else if (isAlarm && alarms != null && !alarms.isEmpty()) {
    // 只有告警没有日志的情况
    RawAlarm firstAlarm = alarms.get(0);
    if (firstAlarm != null && firstAlarm.getLogType() != null) {
        finalNode.setLogType(firstAlarm.getLogType());
        finalNode.setOpType(firstAlarm.getOpType());
        
        // 设置告警信息
        AlarmNodeInfo alarmInfo = convertToAlarmNodeInfo(firstAlarm);
        chainNode.setAlarmNodeInfo(alarmInfo);
        finalNode.setNodeThreatSeverity(...);
    }
}
```

#### 修复效果

**修复前**（domain 实体节点）：
```json
{
  "nodeId": "xxx_DOMAIN_baidu.com",
  "logType": "domain",
  "chainNode": {
    "isAlarm": true,  ← 错误
    "alarmNodeInfo": { ... },  ← 错误：不应该有
    "processEntity": { ... },  ← 错误：不应该有
    "entity": {
      "requestDomain": "baidu.com",
      ...
    }
  }
}
```

**修复后**（domain 实体节点）：
```json
{
  "nodeId": "xxx_DOMAIN_baidu.com",
  "logType": "domain",
  "chainNode": {
    "isAlarm": false,  ← 正确
    "alarmNodeInfo": null,  ← 正确：没有告警信息
    "processEntity": null,  ← 正确：没有进程实体
    "entity": {
      "requestDomain": "baidu.com",
      ...
    }
  }
}
```

**进程节点**（正常）：
```json
{
  "nodeId": "CHILD_123",
  "logType": "process",
  "chainNode": {
    "isAlarm": true,
    "alarmNodeInfo": { ... },  ← 正确：有告警信息
    "processEntity": { ... },  ← 正确：有进程实体
    "entity": null  ← 正确：没有实体
  }
}
```

---

## 节点类型与字段对应关系

| 节点类型 | nodeType | alarmNodeInfo | processEntity | entity |
|---------|----------|--------------|---------------|---------|
| 进程节点（有告警） | `process` | ✅ 有 | ✅ 有 | ❌ null |
| 进程节点（无告警） | `process` | ❌ null | ✅ 有 | ❌ null |
| file 实体节点 | `file_entity` | ❌ null | ❌ null | ✅ FileEntity |
| domain 实体节点 | `domain_entity` | ❌ null | ❌ null | ✅ DomainEntity |
| network 实体节点 | `network_entity` | ❌ null | ❌ null | ✅ NetworkEntity |
| registry 实体节点 | `registry_entity` | ❌ null | ❌ null | ✅ RegistryEntity |

---

## 修改文件总结

| 文件 | 修改内容 | 行数变化 |
|-----|---------|---------|
| `LogNodeSplitter.java` | 为虚拟日志添加 eventId 标记 | +2 |
| `IncidentConverters.java` | 1. 优化日志选择逻辑（优先选择非虚拟日志）<br/>2. 告警信息只设置到进程节点<br/>3. 实体节点明确不设置告警和进程实体 | +87 |

---

## 测试验证

### 测试用例1：验证 opType 保留

**输入**：
```json
{
  "logType": "process",
  "opType": "terminate",
  "processGuid": "CHILD_123",
  "parentProcessGuid": "PARENT_456"
}
```

**预期输出**：
- 子进程节点的 opType 应该是 "terminate"
- 虚拟父节点的 opType 是 "create"（合理）

### 测试用例2：验证实体节点字段

**输入**：
```json
{
  "logType": "domain",
  "processGuid": "xxx",
  "requestDomain": "baidu.com"
}
```

**预期输出**：
```json
{
  "nodeId": "xxx_DOMAIN_xxx",
  "logType": "domain",
  "chainNode": {
    "alarmNodeInfo": null,  ← 应该为 null
    "processEntity": null,  ← 应该为 null
    "entity": {
      "requestDomain": "baidu.com",
      ...
    }
  }
}
```

### 测试用例3：验证进程节点字段

**输入**：process 日志 + 告警

**预期输出**：
```json
{
  "nodeId": "xxx",
  "logType": "process",
  "chainNode": {
    "alarmNodeInfo": { ... },  ← 应该有值
    "processEntity": { ... },  ← 应该有值
    "entity": null  ← 应该为 null
  }
}
```

---

## 总结

### 问题1：opType 覆盖问题 ✅

**根因**：虚拟日志混入真实节点，导致 `getLatestLog` 选到虚拟日志

**修复**：
1. 为虚拟日志添加 `VIRTUAL_LOG_` 前缀标记
2. 在选择日志时优先选择非虚拟日志

**效果**：子进程节点保留原始的 opType，虚拟父节点仍是 "create"

### 问题2：实体节点多余字段 ✅

**根因**：告警处理逻辑没有区分节点类型

**修复**：
1. 告警信息只设置到进程节点
2. 实体节点明确设置 `alarmNodeInfo = null`
3. 实体节点只设置 entity 字段

**效果**：实体节点只有 entity，进程节点有 alarmNodeInfo + processEntity

---

**修改时间**：2025-05-26  
**修改文件**：`LogNodeSplitter.java`, `IncidentConverters.java`  
**测试状态**：✅ 无编译错误，待集成测试验证



