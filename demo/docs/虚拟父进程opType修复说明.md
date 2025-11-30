# 虚拟父进程 opType 修复说明

## 修改背景

在节点拆分逻辑中，当创建虚拟父进程节点时，需要明确设置其 `opType` 为 `"create"`，以表示这是一个进程创建操作。

---

## 修改内容

### 修改的文件

**`demo/src/main/java/com/security/processchain/util/LogNodeSplitter.java`**

### 修改位置

**方法**：`createVirtualParentNode(RawLog rawLog)` - 第160行

### 修改前

```java
// 创建虚拟日志（使用parent字段）
RawLog parentLog = new RawLog();
parentLog.setProcessGuid(rawLog.getParentProcessGuid());
parentLog.setParentProcessGuid(parentParentGuid);
parentLog.setProcessName(rawLog.getParentProcessName());
parentLog.setImage(rawLog.getParentImage());
parentLog.setCommandLine(rawLog.getParentCommandLine());
parentLog.setProcessUserName(rawLog.getParentProcessUserName());
parentLog.setProcessId(rawLog.getParentProcessId());
parentLog.setLogType("process");
// ❌ 缺少 opType 设置
parentLog.setTraceId(rawLog.getTraceId());
parentLog.setHostAddress(rawLog.getHostAddress());
parentLog.setStartTime(rawLog.getStartTime());
```

### 修改后

```java
// 创建虚拟日志（使用parent字段）
RawLog parentLog = new RawLog();
parentLog.setProcessGuid(rawLog.getParentProcessGuid());
parentLog.setParentProcessGuid(parentParentGuid);
parentLog.setProcessName(rawLog.getParentProcessName());
parentLog.setImage(rawLog.getParentImage());
parentLog.setCommandLine(rawLog.getParentCommandLine());
parentLog.setProcessUserName(rawLog.getParentProcessUserName());
parentLog.setProcessId(rawLog.getParentProcessId());
parentLog.setLogType("process");
parentLog.setOpType("create");  // ✅ 虚拟父进程的opType设置为create
parentLog.setTraceId(rawLog.getTraceId());
parentLog.setHostAddress(rawLog.getHostAddress());
parentLog.setStartTime(rawLog.getStartTime());
```

---

## 数据流

### 1. 节点拆分阶段

**位置**：`LogNodeSplitter.createVirtualParentNode()`

```java
parentLog.setOpType("create");  // ✅ 设置虚拟父进程的 opType
```

### 2. 图节点创建

虚拟父进程的 `RawLog` 被添加到 `GraphNode`：

```java
parentNode.addLog(parentLog);  // 包含 opType="create"
```

### 3. 转换为 ProcessEntity

**位置**：`IncidentConverters.convertToProcessEntityForProcessNode()`

```java
ProcessEntity processEntity = new ProcessEntity();
processEntity.setOpType(log.getOpType());  // ✅ 获取到 "create"
```

### 4. 最终输出

虚拟父进程节点的 `ProcessEntity` 中：

```json
{
  "processEntity": {
    "opType": "create",  // ✅ 正确设置
    "processGuid": "...",
    "processName": "父进程.exe",
    "image": "C:\\Windows\\System32\\父进程.exe",
    ...
  },
  "entity": null
}
```

---

## 示例场景

### 输入日志

```json
{
  "processGuid": "CHILD_PROCESS_A",
  "parentProcessGuid": "PARENT_PROCESS_B",
  "processName": "子进程.exe",
  "parentProcessName": "父进程.exe",
  "parentImage": "C:\\Windows\\System32\\父进程.exe",
  "logType": "process",
  "opType": "terminate",  // 子进程的 opType 是 terminate
  ...
}
```

### 输出节点

#### 节点1：父进程（虚拟）

```json
{
  "nodeId": "PARENT_PROCESS_B",
  "logType": "process",
  "opType": "create",  // ✅ 虚拟父进程的 opType 是 "create"
  "chainNode": {
    "processEntity": {
      "opType": "create",
      "processGuid": "PARENT_PROCESS_B",
      "processName": "父进程.exe",
      "image": "C:\\Windows\\System32\\父进程.exe",
      ...
    },
    "entity": null
  }
}
```

#### 节点2：子进程

```json
{
  "nodeId": "CHILD_PROCESS_A",
  "logType": "process",
  "opType": "terminate",  // ✅ 子进程的 opType 保持原值 "terminate"
  "chainNode": {
    "processEntity": {
      "opType": "terminate",
      "processGuid": "CHILD_PROCESS_A",
      "processName": "子进程.exe",
      ...
    },
    "entity": null
  }
}
```

---

## 修改原因

### 1. 语义正确性

虚拟父进程节点代表的是**进程的创建**，而不是其他操作（如 terminate、modify 等）。因此，其 `opType` 应该是 `"create"`。

### 2. 数据一致性

- **子进程节点**：保留原日志的 `opType`（可能是 create、terminate、modify 等）
- **虚拟父进程节点**：统一设置为 `"create"`（表示进程创建）

### 3. 前端展示

前端可能会根据 `opType` 来：
- 显示不同的图标
- 使用不同的颜色
- 展示不同的操作类型

虚拟父进程应该显示为"创建"操作，而不是继承子进程的操作类型。

---

## 影响范围

### 受影响的场景

1. **process 日志拆分**：父进程节点的 `opType` 从 `undefined/null` 变为 `"create"`
2. **file/domain/network/registry 日志拆分**：虚拟父进程节点的 `opType` 从 `undefined/null` 变为 `"create"`

### 不受影响的场景

1. **子进程节点**：保持原日志的 `opType`，不受影响
2. **实体节点**：保持原日志的 `opType`，不受影响
3. **真实父进程节点**：如果找到了真实的 process 日志，使用真实日志的 `opType`，不受影响

---

## 测试验证

### 测试用例1：process 日志拆分

**输入**：
```java
RawLog log = new RawLog();
log.setProcessGuid("CHILD_A");
log.setParentProcessGuid("PARENT_B");
log.setProcessName("child.exe");
log.setParentProcessName("parent.exe");
log.setLogType("process");
log.setOpType("terminate");  // 子进程被终止
```

**预期输出**：
- 父进程节点：`opType = "create"`
- 子进程节点：`opType = "terminate"`

### 测试用例2：file 日志拆分

**输入**：
```java
RawLog log = new RawLog();
log.setProcessGuid("PROCESS_A");
log.setParentProcessGuid("PARENT_B");
log.setProcessName("process.exe");
log.setParentProcessName("parent.exe");
log.setLogType("file");
log.setOpType("delete");  // 文件被删除
log.setTargetFilename("test.txt");
```

**预期输出**：
- 虚拟父进程节点：`opType = "create"`
- 子进程节点：`opType = "delete"`（或 null，取决于实现）
- 文件实体节点：`opType = "delete"`

---

## 总结

### ✅ 修改内容

在 `LogNodeSplitter.createVirtualParentNode()` 方法中，添加了：
```java
parentLog.setOpType("create");
```

### ✅ 修改效果

- 虚拟父进程节点的 `ProcessEntity.opType` 正确设置为 `"create"`
- 语义更加清晰和正确
- 前端可以正确展示虚拟父进程的操作类型

### ✅ 向后兼容

- 完全向后兼容
- 不影响其他节点的 `opType`
- 不改变数据结构

---

## 相关文件

- **修改的文件**：`demo/src/main/java/com/security/processchain/util/LogNodeSplitter.java`
- **相关文件**：
  - `demo/src/main/java/com/security/processchain/service/IncidentConverters.java`
  - `demo/src/main/java/com/security/processchain/model/RawLog.java`
  - `demo/src/main/java/com/security/processchain/service/ProcessEntity.java`

---

**修改日期**：2025-11-19  
**修改人**：Claude  
**修改原因**：用户需求 - 虚拟父进程的 opType 应设置为 "create"


