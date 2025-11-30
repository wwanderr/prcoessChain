# 根节点父节点ID冲突修复说明

**日期**：2025-05-26  
**问题**：根节点的虚拟父节点与子节点ID相同，导致节点合并/覆盖  
**修改文件**：`LogNodeSplitter.java`

---

## 问题描述

### 场景

当日志是**根节点**时（`processGuid == parentProcessGuid`）：

```json
{
  "processGuid": "E3E5C129C46B2111",
  "parentProcessGuid": "E3E5C129C46B2111",  // ← 相同！
  "logType": "file",
  "targetFilename": "bello.php"
}
```

### 问题

按原有的节点拆分逻辑：

```
1. 子进程节点：
   nodeId = "E3E5C129C46B2111"
   
2. 虚拟父节点：
   nodeId = "E3E5C129C46B2111"  // ← 与子节点相同！
   
3. 实体节点：
   nodeId = "E3E5C129C46B2111_FILE_xxx"
```

**结果**：父节点和子节点的 `nodeId` 相同，导致：
- 在 `ProcessChainGraph` 中只有一个节点
- 父节点被子节点覆盖或合并
- 最终图中看不到父节点

### 根本原因

虚拟父节点的 `nodeId` 直接使用了 `rawLog.getParentProcessGuid()`：

```java
// 原代码
parentNode.setNodeId(rawLog.getParentProcessGuid());
```

对于根节点，`parentProcessGuid == processGuid`，导致ID冲突。

---

## 解决方案

### 核心思路

**检测根节点 + 生成特殊父节点ID**

1. 在节点拆分时检测根节点（`processGuid == parentProcessGuid`）
2. 对于根节点，为虚拟父节点生成一个特殊的ID
3. 特殊ID格式：`VIRTUAL_ROOT_PARENT_<hash>`

### 示例

```
原始日志：
  processGuid: E3E5C129C46B2111
  parentProcessGuid: E3E5C129C46B2111

拆分后：
1. 子进程节点：
   nodeId = "E3E5C129C46B2111"
   
2. 虚拟父节点：
   nodeId = "VIRTUAL_ROOT_PARENT_a3f4d2e1"  // ← 生成的特殊ID
   
3. 实体节点：
   nodeId = "E3E5C129C46B2111_FILE_xxx"

边关系：
   VIRTUAL_ROOT_PARENT_a3f4d2e1 → E3E5C129C46B2111 → E3E5C129C46B2111_FILE_xxx
```

---

## 代码实现

### 1. 添加根节点检测逻辑

**位置**：`splitEntityLog()` 和 `splitProcessLog()` 方法

```java
// 2. 创建父进程节点
String parentGuid = rawLog.getParentProcessGuid();
if (parentGuid != null && !parentGuid.isEmpty()) {
    // ⚠️ 检测根节点：processGuid == parentProcessGuid
    boolean isRootNode = childGuid.equals(parentGuid);
    
    GraphNode parentNode;
    String actualParentNodeId;
    
    if (isRootNode) {
        // 根节点：为虚拟父节点生成特殊ID，避免与子节点冲突
        actualParentNodeId = generateVirtualRootParentId(parentGuid);
        parentNode = createVirtualParentNode(rawLog, actualParentNodeId);
        log.debug("【节点拆分】根节点检测: childGuid={} == parentGuid={}, 生成虚拟父节点ID={}", 
                 childGuid, parentGuid, actualParentNodeId);
    } else {
        // 非根节点：使用原始parentGuid
        actualParentNodeId = parentGuid;
        parentNode = createVirtualParentNode(rawLog, actualParentNodeId);
    }
    
    result.setParentNode(parentNode);
    
    // 边1：父 → 子（使用实际的父节点ID）
    result.addEdge(actualParentNodeId, childGuid);
}
```

**关键点**：
1. 检测：`boolean isRootNode = childGuid.equals(parentGuid)`
2. 根节点：生成特殊ID → `generateVirtualRootParentId(parentGuid)`
3. 非根节点：使用原始ID → `actualParentNodeId = parentGuid`
4. 边关系使用 `actualParentNodeId`

### 2. 修改 createVirtualParentNode 方法

**修改前**：

```java
private static GraphNode createVirtualParentNode(RawLog rawLog) {
    GraphNode parentNode = new GraphNode();
    parentNode.setNodeId(rawLog.getParentProcessGuid());  // ← 直接使用parentGuid
    // ...
}
```

**修改后**：

```java
/**
 * 创建虚拟父进程节点
 * 
 * @param rawLog 原始日志
 * @param actualParentNodeId 实际的父节点ID（可能是原始parentGuid，也可能是生成的虚拟ID）
 * @return 虚拟父节点
 */
private static GraphNode createVirtualParentNode(RawLog rawLog, String actualParentNodeId) {
    GraphNode parentNode = new GraphNode();
    parentNode.setNodeId(actualParentNodeId);  // ← 使用传入的实际ID
    
    // 创建虚拟日志
    RawLog parentLog = new RawLog();
    parentLog.setProcessGuid(actualParentNodeId);  // ← 也使用实际ID
    // ...
}
```

**关键变化**：
- 添加参数 `actualParentNodeId`
- `nodeId` 和虚拟日志的 `processGuid` 都使用实际的父节点ID

### 3. 添加 generateVirtualRootParentId 方法

```java
/**
 * 为根节点生成虚拟父节点ID
 * 
 * 根节点特征：processGuid == parentProcessGuid
 * 为避免与子节点ID冲突，生成特殊的父节点ID
 * 
 * @param originalParentGuid 原始的parentProcessGuid
 * @return 虚拟父节点ID，格式：VIRTUAL_ROOT_PARENT_<hash>
 */
private static String generateVirtualRootParentId(String originalParentGuid) {
    if (originalParentGuid == null || originalParentGuid.isEmpty()) {
        return "VIRTUAL_ROOT_PARENT_UNKNOWN";
    }
    
    // 使用原始GUID + "ROOT_PARENT" 计算hash
    String hashInput = originalParentGuid + "_ROOT_PARENT";
    String hash = calculateHash(hashInput);
    
    return "VIRTUAL_ROOT_PARENT_" + hash;
}
```

**生成逻辑**：
1. 输入：`E3E5C129C46B2111`
2. Hash输入：`E3E5C129C46B2111_ROOT_PARENT`
3. 计算MD5前8位：`a3f4d2e1`
4. 输出：`VIRTUAL_ROOT_PARENT_a3f4d2e1`

**特点**：
- ✅ 唯一性：每个原始GUID对应唯一的虚拟父节点ID
- ✅ 可读性：前缀 `VIRTUAL_ROOT_PARENT_` 表明这是虚拟根父节点
- ✅ 简洁性：只保留8位hash，避免ID过长

---

## 效果对比

### 修复前

```
日志：
  processGuid: E3E5C129C46B2111
  parentProcessGuid: E3E5C129C46B2111

节点：
  ❌ 只有1个节点：E3E5C129C46B2111（父节点被覆盖）

边：
  E3E5C129C46B2111 → E3E5C129C46B2111（自环）
```

### 修复后

```
日志：
  processGuid: E3E5C129C46B2111
  parentProcessGuid: E3E5C129C46B2111

节点：
  ✅ 2个节点：
     - VIRTUAL_ROOT_PARENT_a3f4d2e1（虚拟父节点）
     - E3E5C129C46B2111（子节点）

边：
  VIRTUAL_ROOT_PARENT_a3f4d2e1 → E3E5C129C46B2111
```

---

## 适用场景

### 场景1：根节点（process日志）

```json
{
  "logType": "process",
  "opType": "create",
  "processGuid": "ROOT_123",
  "parentProcessGuid": "ROOT_123"
}
```

**拆分结果**：
```
虚拟父节点: VIRTUAL_ROOT_PARENT_<hash>
     ↓
子进程节点: ROOT_123
```

### 场景2：根节点（file日志）

```json
{
  "logType": "file",
  "opType": "create",
  "processGuid": "ROOT_456",
  "parentProcessGuid": "ROOT_456",
  "targetFilename": "malware.exe"
}
```

**拆分结果**：
```
虚拟父节点: VIRTUAL_ROOT_PARENT_<hash>
     ↓
子进程节点: ROOT_456
     ↓
实体节点: ROOT_456_FILE_<hash>
```

### 场景3：非根节点（正常父子关系）

```json
{
  "logType": "file",
  "processGuid": "CHILD_789",
  "parentProcessGuid": "PARENT_012",
  "targetFilename": "test.txt"
}
```

**拆分结果**（无变化）：
```
父进程节点: PARENT_012
     ↓
子进程节点: CHILD_789
     ↓
实体节点: CHILD_789_FILE_<hash>
```

---

## 调试日志

### 根节点检测日志

```
【节点拆分】根节点检测: childGuid=E3E5C129C46B2111 == parentGuid=E3E5C129C46B2111, 
                        生成虚拟父节点ID=VIRTUAL_ROOT_PARENT_a3f4d2e1
```

### 节点拆分日志

```
【节点拆分】process: VIRTUAL_ROOT_PARENT_a3f4d2e1 → E3E5C129C46B2111
【节点拆分】file: VIRTUAL_ROOT_PARENT_a3f4d2e1 → E3E5C129C46B2111 → E3E5C129C46B2111_FILE_xxx
```

---

## 注意事项

### 1. 虚拟父节点的标识

虚拟父节点通过以下方式识别：
- `GraphNode.isVirtual() == true`
- `nodeId` 以 `VIRTUAL_ROOT_PARENT_` 开头（仅根节点）

### 2. 虚拟父节点的合并

在 `ProcessChainGraphBuilder` 的阶段2.5中：
- 如果图中已有真实节点（告警或其他日志），虚拟父节点会被跳过
- 如果图中没有真实节点，虚拟父节点会被添加

### 3. 边关系

所有边关系都使用 `actualParentNodeId`，确保一致性：

```java
result.addEdge(actualParentNodeId, childGuid);
```

### 4. 虚拟父节点的字段

虚拟父节点的 `processGuid` 字段设置为 `actualParentNodeId`：

```java
parentLog.setProcessGuid(actualParentNodeId);
```

这确保了虚拟日志的 `processGuid` 与节点的 `nodeId` 一致。

---

## 测试建议

### 测试用例1：根节点（file日志）

**输入**：
```json
{
  "logType": "file",
  "processGuid": "E3E5C129C46B2111",
  "parentProcessGuid": "E3E5C129C46B2111",
  "targetFilename": "bello.php",
  "traceId": "E3E5C129C46B2111"
}
```

**预期**：
- 节点数量：3（虚拟父节点 + 子节点 + 实体节点）
- 虚拟父节点ID：`VIRTUAL_ROOT_PARENT_<hash>`
- 边关系：`VIRTUAL_ROOT_PARENT_<hash> → E3E5C129C46B2111 → E3E5C129C46B2111_FILE_<hash>`

### 测试用例2：根节点（process日志）

**输入**：
```json
{
  "logType": "process",
  "opType": "create",
  "processGuid": "ROOT_123",
  "parentProcessGuid": "ROOT_123"
}
```

**预期**：
- 节点数量：2（虚拟父节点 + 子节点）
- 虚拟父节点ID：`VIRTUAL_ROOT_PARENT_<hash>`
- 边关系：`VIRTUAL_ROOT_PARENT_<hash> → ROOT_123`

### 测试用例3：非根节点

**输入**：
```json
{
  "logType": "file",
  "processGuid": "CHILD_789",
  "parentProcessGuid": "PARENT_012",
  "targetFilename": "test.txt"
}
```

**预期**：
- 节点数量：3（父节点 + 子节点 + 实体节点）
- 父节点ID：`PARENT_012`（未生成特殊ID）
- 边关系：`PARENT_012 → CHILD_789 → CHILD_789_FILE_<hash>`

---

## 总结

### 问题

根节点的虚拟父节点与子节点ID相同，导致节点冲突。

### 解决方案

1. **检测根节点**：`processGuid == parentProcessGuid`
2. **生成特殊ID**：`VIRTUAL_ROOT_PARENT_<hash>`
3. **更新边关系**：使用特殊ID作为父节点

### 影响范围

- ✅ 修复了根节点的父节点缺失问题
- ✅ 不影响非根节点的处理逻辑
- ✅ 虚拟父节点的合并逻辑保持不变

### 修改文件

- `LogNodeSplitter.java`（3处修改 + 1个新方法）

---

**修改时间**：2025-05-26  
**测试状态**：✅ 无编译错误  
**部署建议**：需要完整回归测试，特别关注根节点场景



