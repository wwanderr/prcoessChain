# traceIdToRootNodeMap 优化说明

## 📋 优化概述

将 `traceIdToRootNodeMap` 从 `IncidentProcessChain` 数据模型中移除，改为通过方法参数传递。

---

## 🎯 优化目标

### 问题分析

**原设计**：`traceIdToRootNodeMap` 作为 `IncidentProcessChain` 的一个字段

```java
public class IncidentProcessChain {
    private List<ProcessNode> nodes;           // 业务数据
    private List<ProcessEdge> edges;           // 业务数据
    private List<String> traceIds;             // 业务数据
    private List<String> hostAddresses;        // 业务数据
    private ThreatSeverity threatSeverity;     // 业务数据
    private Map<String, String> traceIdToRootNodeMap;  // ❌ 辅助数据，不应该在这里
}
```

**存在的问题**：

1. **职责混淆**：混淆了**业务数据**和**构建辅助数据**
2. **数据污染**：增加了数据模型的复杂度
3. **序列化问题**：如果返回给前端，会包含不必要的字段
4. **违反设计原则**：数据模型应该只包含业务数据

### 使用场景分析

`traceIdToRootNodeMap` 的**唯一用途**：

```
ProcessChainBuilder.buildProcessChain()
  ↓ 生成 traceIdToRootNodeMap
  
ProcessChainBuilder.buildIncidentChain()
  ↓ 从 ProcessChainResult 获取
  ↓ 设置到 IncidentProcessChain  ← ❌ 问题所在
  
ProcessChainServiceImpl.mergeNetworkAndEndpointChain()
  ↓ 从 IncidentProcessChain 获取  ← ❌ 不应该从这里获取
  ↓ 传递给 createBridgeEdges()
  
ProcessChainServiceImpl.createBridgeEdges()
  ↓ 使用 traceIdToRootNodeMap 创建桥接边
  ↓ IP → traceId → rootNodeId
```

**关键发现**：
- `traceIdToRootNodeMap` 只在 `createBridgeEdges()` 中使用
- 使用后就不再需要
- 不应该成为 `IncidentProcessChain` 的一部分

---

## ✅ 优化方案

### 设计原则

1. **数据模型纯净**：`IncidentProcessChain` 只包含业务数据
2. **参数传递**：构建辅助数据通过方法参数传递
3. **职责清晰**：构建逻辑和数据模型分离

### 优化后的设计

```java
// 1. IncidentProcessChain 只包含业务数据
public class IncidentProcessChain {
    private List<ProcessNode> nodes;           // ✅ 业务数据
    private List<ProcessEdge> edges;           // ✅ 业务数据
    private List<String> traceIds;             // ✅ 业务数据
    private List<String> hostAddresses;        // ✅ 业务数据
    private ThreatSeverity threatSeverity;     // ✅ 业务数据
    // ✅ 不再包含 traceIdToRootNodeMap
}

// 2. ProcessChainBuilder 提供 getter 方法
public class ProcessChainBuilder {
    private Map<String, String> traceIdToRootNodeMap;
    
    // ✅ 提供 getter 方法
    public Map<String, String> getTraceIdToRootNodeMap() {
        return new HashMap<>(traceIdToRootNodeMap);  // 返回副本，防止外部修改
    }
}

// 3. 作为参数传递
ProcessChainBuilder builder = new ProcessChainBuilder();
IncidentProcessChain endpointChain = builder.buildIncidentChain(...);

// ✅ 单独获取 traceIdToRootNodeMap
Map<String, String> traceIdToRootNodeMap = builder.getTraceIdToRootNodeMap();

// ✅ 作为参数传递
return mergeNetworkAndEndpointChain(
    networkChain, 
    endpointChain, 
    hostToTraceId,
    traceIdToRootNodeMap);  // ← 通过参数传递
```

---

## 🔧 具体修改

### 1. ProcessChainBuilder.java

#### 添加 getter 方法

```java
/**
 * 获取 traceId 到根节点ID的映射
 * 用于网端桥接时创建桥接边
 * 
 * @return traceId 到根节点ID的映射（返回副本，防止外部修改）
 */
public Map<String, String> getTraceIdToRootNodeMap() {
    return new HashMap<>(traceIdToRootNodeMap);
}
```

#### 修改 buildIncidentChain() 方法

**修改前**：
```java
incidentChain.setNodes(finalNodes);
incidentChain.setEdges(finalEdges);

// 将 traceId 到根节点的映射传递给 IncidentProcessChain（用于后续桥接）
incidentChain.setTraceIdToRootNodeMap(result.getTraceIdToRootNodeMap());  // ❌ 删除
```

**修改后**：
```java
incidentChain.setNodes(finalNodes);
incidentChain.setEdges(finalEdges);

// ✅ 优化：不再将 traceIdToRootNodeMap 设置到 IncidentProcessChain
// traceIdToRootNodeMap 通过 getTraceIdToRootNodeMap() 方法单独获取
// 作为方法参数传递，而不是作为业务数据模型的一部分
```

---

### 2. IncidentProcessChain.java

#### 删除 traceIdToRootNodeMap 字段

**修改前**：
```java
public class IncidentProcessChain {
    private List<String> traceIds;
    private List<String> hostAddresses;
    private List<ProcessNode> nodes;
    private List<ProcessEdge> edges;
    private ThreatSeverity threatSeverity;
    
    /**
     * traceId 到根节点ID的映射
     * 用于网端桥接：通过 hostToTraceId 可以找到 traceId，再通过此映射找到对应的根节点
     * 特殊情况：如果没有真实根节点，会映射到 "EXPLORE_ROOT" 虚拟节点
     */
    private Map<String, String> traceIdToRootNodeMap;  // ❌ 删除
    
    // getter/setter...
    public Map<String, String> getTraceIdToRootNodeMap() { ... }  // ❌ 删除
    public void setTraceIdToRootNodeMap(...) { ... }  // ❌ 删除
}
```

**修改后**：
```java
public class IncidentProcessChain {
    private List<String> traceIds;
    private List<String> hostAddresses;
    private List<ProcessNode> nodes;
    private List<ProcessEdge> edges;
    private ThreatSeverity threatSeverity;
    
    // ✅ 不再包含 traceIdToRootNodeMap
}
```

#### 删除 Map 导入

**修改前**：
```java
import java.util.List;
import java.util.Map;  // ❌ 删除
```

**修改后**：
```java
import java.util.List;
```

---

### 3. ProcessChainServiceImpl.java

#### 修改 mergeNetworkAndEndpointChain() 方法签名

**修改前**：
```java
/**
 * 合并网侧和端侧进程链
 * 
 * @param networkChain 网侧进程链（包含节点和边）
 * @param endpointChain 端侧进程链（包含 traceIdToRootNodeMap）
 * @param hostToTraceId host到traceId的映射
 * @return 合并后的完整进程链
 */
private IncidentProcessChain mergeNetworkAndEndpointChain(
        Pair<List<ProcessNode>, List<ProcessEdge>> networkChain,
        IncidentProcessChain endpointChain,
        Map<String, String> hostToTraceId) {
```

**修改后**：
```java
/**
 * 合并网侧和端侧进程链
 * 
 * @param networkChain 网侧进程链（包含节点和边）
 * @param endpointChain 端侧进程链
 * @param hostToTraceId host到traceId的映射
 * @param traceIdToRootNodeMap traceId到根节点ID的映射（用于创建桥接边）  // ✅ 新增参数
 * @return 合并后的完整进程链
 */
private IncidentProcessChain mergeNetworkAndEndpointChain(
        Pair<List<ProcessNode>, List<ProcessEdge>> networkChain,
        IncidentProcessChain endpointChain,
        Map<String, String> hostToTraceId,
        Map<String, String> traceIdToRootNodeMap) {  // ✅ 新增参数
```

#### 修改桥接边创建逻辑

**修改前**：
```java
// 5. **关键**：创建桥接边（连接网侧 victim 到端侧根节点）
// 使用 hostToTraceId 和 traceIdToRootNodeMap 联动创建桥接边
if (endpointChain != null && endpointChain.getTraceIdToRootNodeMap() != null) {  // ❌ 从 IncidentProcessChain 获取
    List<ProcessEdge> bridgeEdges = createBridgeEdges(
            networkNodes, 
            hostToTraceId, 
            endpointChain.getTraceIdToRootNodeMap());
    if (bridgeEdges != null && !bridgeEdges.isEmpty()) {
        allEdges.addAll(bridgeEdges);
        log.info("【进程链生成】-> 添加桥接边数: {}", bridgeEdges.size());
    }
} else {
    log.warn("【进程链生成】-> 端侧进程链或 traceIdToRootNodeMap 为空，无法创建桥接边");
}
```

**修改后**：
```java
// 5. **关键**：创建桥接边（连接网侧 victim 到端侧根节点）
// 使用 hostToTraceId 和 traceIdToRootNodeMap 联动创建桥接边
if (traceIdToRootNodeMap != null && !traceIdToRootNodeMap.isEmpty()) {  // ✅ 直接使用参数
    List<ProcessEdge> bridgeEdges = createBridgeEdges(
            networkNodes, 
            hostToTraceId, 
            traceIdToRootNodeMap);
    if (bridgeEdges != null && !bridgeEdges.isEmpty()) {
        allEdges.addAll(bridgeEdges);
        log.info("【进程链生成】-> 添加桥接边数: {}", bridgeEdges.size());
    }
} else {
    log.warn("【进程链生成】-> traceIdToRootNodeMap 为空，无法创建桥接边");
}
```

#### 修改 generateProcessChains() 调用处

**修改前**：
```java
ProcessChainBuilder builder = new ProcessChainBuilder();
IncidentProcessChain endpointChain = builder.buildIncidentChain(
        allSelectedAlarms, allLogs, allTraceIds, allAssociatedEventIds,
        IncidentConverters.NODE_MAPPER, IncidentConverters.EDGE_MAPPER);

// 设置 traceIds 和 hostAddresses
if (endpointChain != null) {
    endpointChain.setTraceIds(new ArrayList<>(allTraceIds));
    endpointChain.setHostAddresses(new ArrayList<>(allHostAddresses));
}

// ... 日志输出 ...
if (endpointChain != null && endpointChain.getTraceIdToRootNodeMap() != null) {  // ❌ 从 IncidentProcessChain 获取
    log.info("【进程链生成】-> traceId到根节点映射数: {}", endpointChain.getTraceIdToRootNodeMap().size());
    log.info("【进程链生成】-> traceId映射详情: {}", endpointChain.getTraceIdToRootNodeMap());
}

// 合并网侧和端侧进程链（使用 hostToTraceId 和 endpointChain 中的 traceIdToRootNodeMap）
return mergeNetworkAndEndpointChain(networkChain, endpointChain, hostToTraceId);  // ❌ 缺少参数
```

**修改后**：
```java
ProcessChainBuilder builder = new ProcessChainBuilder();
IncidentProcessChain endpointChain = builder.buildIncidentChain(
        allSelectedAlarms, allLogs, allTraceIds, allAssociatedEventIds,
        IncidentConverters.NODE_MAPPER, IncidentConverters.EDGE_MAPPER);

// ✅ 优化：单独获取 traceIdToRootNodeMap（不作为 IncidentProcessChain 的一部分）
Map<String, String> traceIdToRootNodeMap = builder.getTraceIdToRootNodeMap();

// 设置 traceIds 和 hostAddresses
if (endpointChain != null) {
    endpointChain.setTraceIds(new ArrayList<>(allTraceIds));
    endpointChain.setHostAddresses(new ArrayList<>(allHostAddresses));
}

// ... 日志输出 ...
if (traceIdToRootNodeMap != null && !traceIdToRootNodeMap.isEmpty()) {  // ✅ 直接使用变量
    log.info("【进程链生成】-> traceId到根节点映射数: {}", traceIdToRootNodeMap.size());
    log.info("【进程链生成】-> traceId映射详情: {}", traceIdToRootNodeMap);
}

// ✅ 优化：将 traceIdToRootNodeMap 作为参数传递，而不是从 IncidentProcessChain 中获取
return mergeNetworkAndEndpointChain(networkChain, endpointChain, hostToTraceId, traceIdToRootNodeMap);
```

---

## 📊 优化效果对比

### 优化前

| 方面 | 状态 | 说明 |
|------|------|------|
| **数据模型** | ❌ 混乱 | 包含业务数据和辅助数据 |
| **职责** | ❌ 不清晰 | 数据模型承担了构建辅助的职责 |
| **序列化** | ❌ 冗余 | 返回给前端时包含不必要的字段 |
| **维护性** | ❌ 较差 | 数据模型复杂度高 |

### 优化后

| 方面 | 状态 | 说明 |
|------|------|------|
| **数据模型** | ✅ 纯净 | 只包含业务数据 |
| **职责** | ✅ 清晰 | 数据模型和构建逻辑分离 |
| **序列化** | ✅ 简洁 | 不包含多余字段 |
| **维护性** | ✅ 优秀 | 数据模型简单明了 |

---

## 🎯 优化总结

### 核心改进

1. **数据模型纯净化**
   - `IncidentProcessChain` 只包含业务数据
   - 移除了构建辅助数据 `traceIdToRootNodeMap`

2. **职责清晰化**
   - `ProcessChainBuilder` 负责构建和提供辅助数据
   - `IncidentProcessChain` 只负责存储业务数据
   - 辅助数据通过方法参数传递

3. **代码可维护性提升**
   - 数据流向更清晰：Builder → getter → 参数传递 → 使用
   - 符合单一职责原则
   - 易于理解和维护

### 设计原则

✅ **单一职责原则**：数据模型只负责存储业务数据  
✅ **关注点分离**：构建逻辑和数据模型分离  
✅ **最小暴露原则**：只暴露必要的业务数据  
✅ **防御性编程**：getter 返回副本，防止外部修改  

### 影响范围

- ✅ **无破坏性修改**：测试文件无需修改
- ✅ **向后兼容**：只是内部实现优化
- ✅ **性能无影响**：只是数据传递方式的改变

---

## 📝 注意事项

1. **测试验证**
   - 所有现有测试用例无需修改
   - 测试文件中没有使用 `getTraceIdToRootNodeMap()` 或 `setTraceIdToRootNodeMap()`

2. **API 兼容性**
   - 如果 `IncidentProcessChain` 作为 API 响应返回给前端
   - 优化后不再包含 `traceIdToRootNodeMap` 字段
   - 这是**正确的行为**，因为前端不需要这个内部辅助数据

3. **扩展性**
   - 如果未来需要其他辅助数据，应该遵循相同的模式
   - 通过 `ProcessChainBuilder` 的 getter 方法提供
   - 通过方法参数传递，而不是添加到 `IncidentProcessChain`

---

## ✅ 修改完成

所有修改已完成，包括：

1. ✅ `ProcessChainBuilder.java`：添加 `getTraceIdToRootNodeMap()` 方法
2. ✅ `ProcessChainBuilder.java`：移除 `buildIncidentChain()` 中设置 `traceIdToRootNodeMap` 的代码
3. ✅ `IncidentProcessChain.java`：删除 `traceIdToRootNodeMap` 字段及其 getter/setter
4. ✅ `IncidentProcessChain.java`：删除 `Map` 导入
5. ✅ `ProcessChainServiceImpl.java`：修改 `mergeNetworkAndEndpointChain()` 方法签名
6. ✅ `ProcessChainServiceImpl.java`：修改桥接边创建逻辑
7. ✅ `ProcessChainServiceImpl.java`：修改 `generateProcessChains()` 调用处

**优化完成！代码更加清晰、简洁、易于维护！** 🎉

