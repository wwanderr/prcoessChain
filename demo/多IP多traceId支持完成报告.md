# 多 IP 多 traceId 支持完成报告

## 修改时间
2025-10-21

## 问题分析

### 原始问题
在 `generateProcessChains` 函数中，系统只基于 `firstTraceId` 去构建进程链，导致：
1. 多个 IP 的进程链被强制使用同一个 traceId
2. 只有第一个 IP 能正确找到根节点（因为 `processGuid == traceId` 判断）
3. 其他 IP 的进程链都会被误判为断链

### 根本原因
`ProcessChainBuilder` 在判断根节点时使用：
```java
if (currentProcessGuid.equals(traceId)) {  // 只能匹配一个 traceId
    foundRootNode = true;
    rootNodes.add(currentProcessGuid);
}
```

当多个 IP 有不同的 traceId 时（例如 T1, T2, T3），但系统只用 firstTraceId（T1）构建，导致：
- IP1 (T1): ✅ 能找到根节点
- IP2 (T2): ❌ 找不到根节点 → 被标记为断链
- IP3 (T3): ❌ 找不到根节点 → 被标记为断链 

---

## 解决方案

### 核心思路
将 `IncidentProcessChain` 的 `traceId` 和 `hostAddress` 改为 `List`，并支持多个 traceId 的根节点判断。

### 修改内容

#### 1. 修改 `IncidentProcessChain.java`

**变更**：
- `String traceId` → `List<String> traceIds`
- `String hostAddress` → `List<String> hostAddresses`

**目的**：支持存储多个 IP 和多个 traceId

```java
public class IncidentProcessChain {
    private List<String> traceIds;        // 改为 List
    private List<String> hostAddresses;   // 改为 List
    private List<ProcessNode> nodes;
    private List<ProcessEdge> edges;
    private ThreatSeverity threatSeverity;
    // ...
}
```

---

#### 2. 修改 `ProcessChainBuilder.java`

**核心变更**：所有方法的 `traceId` 参数改为 `Set<String> traceIds`

##### 2.1 `buildProcessChain` 方法
```java
// 旧签名
public ProcessChainResult buildProcessChain(
    List<RawAlarm> alarms, 
    List<RawLog> logs, 
    String traceId,  // ❌ 单个
    String associatedEventId)

// 新签名
public ProcessChainResult buildProcessChain(
    List<RawAlarm> alarms, 
    List<RawLog> logs, 
    Set<String> traceIds,  // ✅ 多个
    String associatedEventId)
```

##### 2.2 `buildBidirectionalChain` 方法
```java
private void buildBidirectionalChain(
    RawAlarm alarm, 
    Map<String, List<RawLog>> logsByProcessGuid,
    Map<String, List<RawLog>> logsByParentProcessGuid,
    Set<String> traceIds) {  // 改为 Set
    
    // 检查告警节点本身是否是根节点
    if (traceIds.contains(processGuid)) {  // 改为 contains
        foundRootNode = true;
        rootNodes.add(processGuid);
        log.info("【进程链生成】-> 告警节点本身就是根节点: processGuid={} (匹配traceIds)", processGuid);
    }
    // ...
}
```

##### 2.3 `buildUpwardChain` 方法
```java
private void buildUpwardChain(
    RawAlarm alarm, 
    Map<String, List<RawLog>> logsByProcessGuid,
    Set<String> traceIds) {  // 改为 Set
    
    // 检查告警节点本身是否是根节点
    if (traceIds.contains(processGuid)) {  // 改为 contains
        foundRootNode = true;
        rootNodes.add(processGuid);
    }
    // ...
}
```

##### 2.4 `traverseUpward` 方法（核心修改）
```java
private void traverseUpward(
    String currentProcessGuid, 
    Map<String, List<RawLog>> logsByProcessGuid,
    Set<String> traceIds,  // 改为 Set
    int depth) {
    
    // 检查当前节点是否是任意一个 traceId 的根节点
    if (traceIds.contains(currentProcessGuid)) {  // 改为 contains
        foundRootNode = true;
        rootNodes.add(currentProcessGuid);
        log.info("【进程链生成】-> 找到根节点: processGuid={} (匹配traceIds)", currentProcessGuid);
        return;
    }
    // ...
}
```

##### 2.5 新增 `buildIncidentChain` 方法
```java
public IncidentProcessChain buildIncidentChain(
        List<RawAlarm> alarms, 
        List<RawLog> logs,
        Set<String> traceIds,  // 接受多个 traceId
        String associatedEventId,
        NodeMapper nodeMapper, 
        EdgeMapper edgeMapper) {
    
    // 构建内部结果
    ProcessChainResult result = buildProcessChain(alarms, logs, traceIds, associatedEventId);
    
    // 转换为最终的 IncidentProcessChain
    // ... 转换逻辑 ...
    
    return incidentChain;
}
```

##### 2.6 保留旧方法（向后兼容）
```java
@Deprecated
public IncidentProcessChain buildIncidentChain(
        List<RawAlarm> alarms, 
        List<RawLog> logs,
        String traceId,  // 旧版单个 traceId
        String associatedEventId,
        NodeMapper nodeMapper, 
        EdgeMapper edgeMapper) {
    // 转换为新方法
    Set<String> traceIds = new HashSet<>();
    if (traceId != null && !traceId.trim().isEmpty()) {
        traceIds.add(traceId);
    }
    return buildIncidentChain(alarms, logs, traceIds, associatedEventId, nodeMapper, edgeMapper);
}
```

---

#### 3. 修改 `ProcessChainServiceImpl.java`

##### 3.1 收集所有 traceId 和 hostAddress
```java
// 新增变量
Set<String> allTraceIds = new HashSet<>();
Set<String> allHostAddresses = new HashSet<>();

// 在阶段1中收集
for (String ip : ips) {
    // ... 查询和选择告警 ...
    
    // 收集所有 traceId 和 hostAddress
    if (firstAlarm.getTraceId() != null) {
        allTraceIds.add(firstAlarm.getTraceId());
    }
    if (firstAlarm.getHostAddress() != null) {
        allHostAddresses.add(firstAlarm.getHostAddress());
    }
    
    // 记录 host -> traceId 的映射
    hostToTraceId.put(firstAlarm.getHostAddress(), firstAlarm.getTraceId());
}
```

##### 3.2 传入所有 traceId 构建进程链
```java
// 阶段3: 构建端侧进程链
log.info("【进程链生成】-> 收集到的 traceId 数量: {}, hostAddress 数量: {}", 
        allTraceIds.size(), allHostAddresses.size());
log.info("【进程链生成】-> traceIds: {}", allTraceIds);

ProcessChainBuilder builder = new ProcessChainBuilder();
IncidentProcessChain endpointChain = builder.buildIncidentChain(
        allSelectedAlarms, 
        allLogs, 
        allTraceIds,  // ✅ 传入所有 traceId
        null,
        IncidentConverters.NODE_MAPPER, 
        IncidentConverters.EDGE_MAPPER);

// 设置 traceIds 和 hostAddresses
if (endpointChain != null) {
    endpointChain.setTraceIds(new ArrayList<>(allTraceIds));
    endpointChain.setHostAddresses(new ArrayList<>(allHostAddresses));
}
```

##### 3.3 修改 `mergeNetworkAndEndpointChain` 方法
```java
// 7. 设置基本信息（使用端侧的信息）
if (endpointChain != null) {
    mergedChain.setTraceIds(endpointChain.getTraceIds());           // 改为 List
    mergedChain.setHostAddresses(endpointChain.getHostAddresses()); // 改为 List
    mergedChain.setThreatSeverity(endpointChain.getThreatSeverity());
}
```

##### 3.4 修改单个 IP 的进程链生成
```java
public IncidentProcessChain generateProcessChainForIp(
        String ip, String associatedEventId, boolean hasAssociation) {
    
    // ... 查询告警和日志 ...
    
    // 构建进程链
    Set<String> traceIds = new HashSet<>();
    traceIds.add(firstAlarm.getTraceId());  // 单个 IP 只有一个 traceId
    
    ProcessChainBuilder builder = new ProcessChainBuilder();
    IncidentProcessChain incidentChain = builder.buildIncidentChain(
        selectedAlarms, 
        logs, 
        traceIds,  // 传入 Set
        associatedEventId,
        IncidentConverters.NODE_MAPPER, 
        IncidentConverters.EDGE_MAPPER);
    
    // 设置基本信息
    if (incidentChain != null) {
        List<String> traceIdList = new ArrayList<>();
        traceIdList.add(firstAlarm.getTraceId());
        incidentChain.setTraceIds(traceIdList);
        
        List<String> hostAddressList = new ArrayList<>();
        hostAddressList.add(firstAlarm.getHostAddress());
        incidentChain.setHostAddresses(hostAddressList);
    }
    
    return incidentChain;
}
```

---

## 修改效果

### 修改前
```
输入: 3个IP，traceIds = [T1, T2, T3]
构建: 只用 firstTraceId = T1
结果:
  - IP1 (T1): ✅ 找到根节点
  - IP2 (T2): ❌ 断链（T2 != T1）
  - IP3 (T3): ❌ 断链（T3 != T1）
```

### 修改后
```
输入: 3个IP，traceIds = [T1, T2, T3]
构建: 使用 allTraceIds = {T1, T2, T3}
结果:
  - IP1 (T1): ✅ 找到根节点（T1 匹配）
  - IP2 (T2): ✅ 找到根节点（T2 匹配）
  - IP3 (T3): ✅ 找到根节点（T3 匹配）
```

---

## 优点

### 1. 正确性
- ✅ 每个 IP 都能正确找到根节点
- ✅ 不会误判为断链
- ✅ 根节点识别准确

### 2. 灵活性
- ✅ 支持多个 IP 的批量处理
- ✅ 支持单个 IP 的独立处理
- ✅ 向后兼容旧代码（提供 @Deprecated 方法）

### 3. 可扩展性
- ✅ 可以处理任意数量的 IP 和 traceId
- ✅ 自然支持跨 IP 的进程关系（如果存在）

### 4. 性能
- ✅ 一次构建，处理所有 IP
- ✅ 批量查询，减少 ES 请求次数
- ✅ 使用 HashSet 提升查找效率（O(1)）

---

## 兼容性

### 向后兼容
保留了旧的 `buildIncidentChain(String traceId)` 方法：
- 标记为 `@Deprecated`
- 内部调用新方法
- 确保旧代码不会报错

### API 变更
前端需要适配新的 JSON 格式：

**旧格式**：
```json
{
  "traceId": "T1",
  "hostAddress": "10.50.86.171",
  "nodes": [...],
  "edges": [...]
}
```

**新格式**：
```json
{
  "traceIds": ["T1", "T2", "T3"],
  "hostAddresses": ["10.50.86.171", "10.50.86.52", "10.50.86.197"],
  "nodes": [...],
  "edges": [...]
}
```

---

## 测试验证

### 编译检查
✅ 所有 linter 错误已修复，代码编译通过

### 推荐测试场景

#### 场景1：单个 IP
```
输入: 1个IP
期望: traceIds=[T1], hostAddresses=["10.50.86.171"]
```

#### 场景2：多个 IP，不同 traceId
```
输入: 3个IP，各自有不同 traceId
期望: traceIds=[T1,T2,T3], hostAddresses=["IP1","IP2","IP3"]
       每个IP都能找到根节点
```

#### 场景3：多个 IP，相同 traceId
```
输入: 2个IP，共享同一个 traceId
期望: traceIds=[T1], hostAddresses=["IP1","IP2"]
       只有一个根节点
```

#### 场景4：网侧端侧合并
```
输入: 网侧数据 + 端侧多个IP
期望: 正确建立桥接边，所有受害者连接到对应根节点
```

---

## 文件清单

### 修改的文件
1. `demo/src/main/java/com/security/processchain/service/IncidentProcessChain.java`
2. `demo/src/main/java/com/security/processchain/service/ProcessChainBuilder.java`
3. `demo/src/main/java/com/security/processchain/service/impl/ProcessChainServiceImpl.java`

### 新增的文件
无

### 删除的文件
无

---

## 后续建议

### 1. 更新文档
- 更新 API 文档，说明新的返回格式
- 更新 `项目详细说明文档.md`，反映最新的函数签名

### 2. 前端适配
- 修改前端代码，适配 `traceIds` 和 `hostAddresses` 数组
- 显示时可以展示多个 traceId 和 IP

### 3. 性能监控
- 监控多 IP 场景的性能
- 记录 traceId 集合大小和构建时间

### 4. 日志分析
- 检查日志，确认根节点识别正确
- 检查断链标记，确认不再误判

---

## 总结

本次修改解决了多 IP 批量生成进程链时，只使用第一个 IP 的 traceId 导致其他 IP 被误判为断链的严重逻辑错误。

通过将 `traceId` 改为 `Set<String> traceIds`，系统现在能够：
- ✅ 正确识别每个 IP 的根节点
- ✅ 避免误判断链
- ✅ 支持多 IP 的批量处理
- ✅ 保持向后兼容

所有修改已通过编译检查，没有 linter 错误。

