# 节点日志 opType 问题排查

**日期**：2025-05-26  
**问题**：拆分后的进程节点，opType 都变成了 "create"

---

## 问题描述

### 问题1：子进程节点的 opType 都是 "create"

用户反馈：拆分 process 日志后，除了实体节点，其他节点（子进程、父进程）的 opType 都是 "create"。

**预期**：
- 虚拟父节点：opType = "create" ✅ 这是合理的
- 子进程节点：opType = 原始日志的 opType（可能是 "create"、"terminate"、"access" 等）

### 问题2：domain 节点同时有多个字段

domain 类型的节点同时有：
- alarmNodeInfo ❌
- processEntity ❌  
- entity ✅

**预期**：实体节点应该只有 entity 字段。

---

## 根因分析

### 问题1 根因：虚拟日志混入子节点

#### 场景重现

1. **原始日志**：
```json
{
  "logType": "process",
  "opType": "terminate",  ← 原始是 terminate
  "processGuid": "CHILD_123",
  "parentProcessGuid": "PARENT_456"
}
```

2. **节点拆分**：
```
父进程节点（虚拟）:
  nodeId: PARENT_456
  logs: [虚拟日志(logType=process, opType=create)]
  
子进程节点:
  nodeId: CHILD_123
  logs: [原始日志(logType=process, opType=terminate)]
```

3. **节点合并**（阶段2.5）：
如果虚拟父节点被真实节点替代，可能发生：
```
合并后的节点:
  nodeId: PARENT_456
  logs: [
    虚拟日志(opType=create),
    真实日志(opType=terminate)
  ]
```

4. **最终转换**（`IncidentConverters`）：
```java
RawLog latestLog = getLatestLog(logs);  // 可能选到虚拟日志
finalNode.setOpType(latestLog.getOpType());  // opType = "create"
```

#### 问题根源

**`getLatestLog` 选择时间最近的日志**，但：
- 虚拟日志的 `startTime` 可能与真实日志相同
- 如果虚拟日志在列表后面，可能被选中

### 问题2 根因：告警信息处理逻辑

#### 原有逻辑

```java
// 第43-50行：如果有告警，设置 alarmNodeInfo
if (isAlarm) {
    AlarmNodeInfo alarmInfo = convertToAlarmNodeInfo(latestAlarm);
    chainNode.setAlarmNodeInfo(alarmInfo);
}

// 第68-76行：如果是实体节点，设置 entity
if (nodeType != null && nodeType.endsWith("_entity")) {
    chainNode.setEntity(convertToEntity(latestLog, entityType));
}
```

**问题**：这两段逻辑独立执行，如果一个节点既有告警又是实体类型，两个字段都会被设置。

但实际上，**实体节点不应该有告警**！告警只应该关联到进程节点。

---

## 修复方案

### 修复问题2：实体节点不设置告警信息 ✅

**修改位置**：`IncidentConverters.java` 第35-96行

**修改内容**：
1. 将告警信息设置移到 `nodeType == "process"` 的分支内
2. 实体节点分支明确设置 `alarmNodeInfo = null`
3. 兜底逻辑也处理告警

**修改后的逻辑**：

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
    
} else if (nodeType != null && nodeType.endsWith("_entity")) {
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

**效果**：
- 进程节点：有 alarmNodeInfo + processEntity ✅
- 实体节点：只有 entity ✅

### 修复问题1：优化日志选择逻辑（待实施）

**方案A：在 `getLatestLog` 中过滤虚拟日志**

```java
private static RawLog getLatestLog(List<RawLog> logs) {
    if (logs == null || logs.isEmpty()) {
        return null;
    }
    
    // 优先选择非虚拟日志
    List<RawLog> nonVirtualLogs = new ArrayList<>();
    for (RawLog log : logs) {
        if (log != null && !isVirtualLog(log)) {
            nonVirtualLogs.add(log);
        }
    }
    
    // 如果有非虚拟日志，从中选择最新的
    List<RawLog> logsToSelect = nonVirtualLogs.isEmpty() ? logs : nonVirtualLogs;
    
    RawLog latest = null;
    for (RawLog logItem : logsToSelect) {
        if (logItem == null) continue;
        if (latest == null) {
            latest = logItem;
            continue;
        }
        String a = logItem.getStartTime();
        String b = latest.getStartTime();
        if (a != null && (b == null || a.compareTo(b) > 0)) {
            latest = logItem;
        }
    }
    return latest;
}

/**
 * 判断是否为虚拟日志
 * 虚拟日志特征：logType=process + opType=create + 缺少某些字段
 */
private static boolean isVirtualLog(RawLog log) {
    if (log == null) return false;
    
    // 简单判断：如果 eventId 为空，可能是虚拟日志
    // 更准确的判断需要添加额外的标记字段
    return log.getEventId() == null || log.getEventId().isEmpty();
}
```

**方案B：为虚拟日志添加标记**

在 `LogNodeSplitter.createVirtualParentNode` 中：

```java
RawLog parentLog = new RawLog();
// ... 其他字段设置 ...
parentLog.setLogType("process");
parentLog.setOpType("create");

// 添加虚拟标记
parentLog.setEventId("VIRTUAL_LOG");  // 或者在 otherFields 中添加标记
```

然后在 `getLatestLog` 中过滤：

```java
private static boolean isVirtualLog(RawLog log) {
    if (log == null) return false;
    return "VIRTUAL_LOG".equals(log.getEventId());
}
```

**方案C：在节点合并时不合并虚拟日志**

在 `ProcessChainGraphBuilder.mergeLogsWithLimit` 中：

```java
for (RawLog rawLog : newLogs) {
    // 跳过虚拟日志
    if (isVirtualLog(rawLog)) {
        continue;
    }
    
    if (currentLogCount < MAX_LOGS_PER_NODE) {
        targetNode.addLog(rawLog);
        currentLogCount++;
        addedCount++;
    } else {
        skippedCount++;
    }
}
```

---

## 实施步骤

### 已完成 ✅

- [x] 修复问题2：实体节点不设置告警信息和进程实体

### 待实施

- [ ] 为虚拟日志添加明确的标记字段（方案B）
- [ ] 在日志选择逻辑中过滤虚拟日志（方案A）
- [ ] 添加单元测试验证修复效果

---

## 测试建议

### 测试用例1：验证实体节点字段

**输入**：domain 类型日志 + 告警

**预期输出**：
```json
{
  "nodeId": "xxx_DOMAIN_baidu.com",
  "logType": "domain",
  "chainNode": {
    "isAlarm": false,  ← 应该是 false，因为告警在进程节点上
    "alarmNodeInfo": null,  ← 应该为 null
    "processEntity": null,  ← 应该为 null
    "entity": {  ← 只有这个应该有值
      "requestDomain": "baidu.com",
      ...
    }
  }
}
```

### 测试用例2：验证进程节点 opType

**输入**：process 日志，opType = "terminate"

**预期输出**：
```json
{
  "nodeId": "CHILD_123",
  "logType": "process",
  "opType": "terminate",  ← 应该保留原始值
  "chainNode": {
    "processEntity": {
      "opType": "terminate",  ← 应该保留原始值
      ...
    }
  }
}
```

**虚拟父节点输出**（这个是合理的）：
```json
{
  "nodeId": "PARENT_456",
  "logType": "process",
  "opType": "create",  ← 虚拟节点是 create，这是对的
  "chainNode": {
    "processEntity": {
      "opType": "create",
      ...
    }
  }
}
```

---

## 总结

### 问题1：opType 都是 "create"

**根因**：虚拟日志混入真实节点，`getLatestLog` 可能选到虚拟日志

**建议修复**：为虚拟日志添加标记，在选择时过滤

### 问题2：实体节点有多余字段 ✅

**根因**：告警信息处理逻辑没有区分节点类型

**已修复**：只有进程节点才设置告警信息，实体节点只设置 entity

---

**修改时间**：2025-05-26  
**修改文件**：`IncidentConverters.java`  
**测试状态**：问题2已修复，问题1需要进一步排查和修复



