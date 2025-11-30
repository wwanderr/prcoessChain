# 断链节点与EXPLORE节点说明

## 🎯 核心概念

### 1. 根节点（Root Node）

**定义**：进程链的起点节点

**识别条件**：
1. **processGuid == traceId**（真实根节点）
2. **入度为0 且 没有parentProcessGuid**（虚拟根节点）

**示例**：
```
节点A:
  processGuid: TRACE_001
  traceId: TRACE_001
  入度: 0
  
结果: 根节点 ✅
映射: traceIdToRootNodeMap[TRACE_001] = TRACE_001
```

### 2. 断链节点（Broken Node）

**定义**：找不到父节点的节点（日志数据不完整）

**识别条件**：
- **入度为0**（图中没有父节点）
- **有parentProcessGuid**（但这个父节点在日志中不存在）

**示例**：
```
节点B:
  processGuid: PROC_001
  parentProcessGuid: PROC_999  // 这个节点不存在！
  traceId: TRACE_001
  入度: 0
  
结果: 断链节点 ⚠️
不建立映射（等待EXPLORE节点）
```

### 3. EXPLORE节点（虚拟根节点）

**定义**：为断链节点创建的虚拟根节点

**创建时机**：
- 在 `buildIncidentChain()` 的最后阶段
- 调用 `addExploreNodesForBrokenChains()`

**创建条件**：
1. 存在断链节点
2. 或者某个traceId没有真实根节点

**节点ID格式**：`EXPLORE_ROOT_{traceId}`

**示例**：
```
断链节点: PROC_001 (traceId=TRACE_001)

创建EXPLORE节点:
  nodeId: EXPLORE_ROOT_TRACE_001
  logType: "explore"
  isRoot: true
  
建立边: EXPLORE_ROOT_TRACE_001 → PROC_001
建立映射: traceIdToRootNodeMap[TRACE_001] = EXPLORE_ROOT_TRACE_001
```

---

## 🔄 完整流程

### 阶段1：建图（buildProcessChain）

```java
ProcessChainGraph graph = graphBuilder.buildGraph(alarms, logs, traceIds);

// 识别根节点和断链节点
graph.identifyRootNodes(traceIds);

结果：
  - rootNodes: [真实根节点们]
  - brokenNodes: [断链节点们]
  - traceIdToRootNodeMap: {traceId → 真实根节点} 
    ⚠️ 如果只有断链节点，这个映射可能为空！
  - brokenNodeToTraceId: {断链节点 → traceId}
```

### 阶段2：转换（buildIncidentChain）

```java
ProcessChainResult result = builder.buildProcessChain(...);

// 如果有断链节点，创建EXPLORE节点
if (!result.getBrokenNodes().isEmpty() || 有traceId无根节点) {
    addExploreNodesForBrokenChains(...);
}

EXPLORE节点创建后：
  - 为每个没有根节点的traceId创建 EXPLORE_ROOT_{traceId}
  - 更新 traceIdToRootNodeMap: {traceId → EXPLORE节点}
  - 创建边: EXPLORE节点 → 断链节点
```

### 阶段3：网端桥接

```java
// 使用 traceIdToRootNodeMap 创建桥接边
for (victim节点: networkNodes) {
    String traceId = hostToTraceId.get(victimIP);
    String rootNodeId = traceIdToRootNodeMap.get(traceId);
    
    // rootNodeId 可能是真实根节点，也可能是EXPLORE节点
    创建桥接边: victim → rootNodeId
}
```

---

## 📊 场景对比

### 场景1：有真实根节点

```
日志数据完整:
  root (TRACE_001) → A → B (告警)

建图后:
  rootNodes: [TRACE_001]
  brokenNodes: []
  traceIdToRootNodeMap: {TRACE_001: TRACE_001} ✅

EXPLORE节点:
  不创建（已有真实根节点）

网端桥接:
  victim → TRACE_001 ✅
```

### 场景2：有断链节点

```
日志数据不完整:
  B的父节点A在日志中不存在
  B (PROC_001, parentGuid=PROC_999不存在)

建图后:
  rootNodes: []
  brokenNodes: [PROC_001]
  traceIdToRootNodeMap: {} ⚠️ 空的！
  brokenNodeToTraceId: {PROC_001: TRACE_001}

EXPLORE节点:
  创建 EXPLORE_ROOT_TRACE_001
  traceIdToRootNodeMap: {TRACE_001: EXPLORE_ROOT_TRACE_001} ✅
  创建边: EXPLORE_ROOT_TRACE_001 → PROC_001

网端桥接:
  victim → EXPLORE_ROOT_TRACE_001 ✅
```

### 场景3：虚拟父节点（不是断链）

```
日志:
  子进程 (processGuid=PROC_001, parentGuid=PROC_999)
  
建图时创建虚拟父节点:
  虚拟父节点 (processGuid=PROC_999或VIRTUAL_ROOT_XXX)
  入度: 0
  parentGuid: null 或 hash值

识别后:
  rootNodes: [PROC_999或VIRTUAL_ROOT_XXX] ✅ 是根节点，不是断链！
  brokenNodes: []
  traceIdToRootNodeMap: {TRACE_001: PROC_999} ✅

EXPLORE节点:
  不创建（已有根节点）

网端桥接:
  victim → PROC_999 ✅
```

---

## 🐛 晚拆分方案的影响

### 问题

晚拆分方案中，建图阶段不拆分实体，可能导致：
1. 虚拟父节点的创建逻辑改变
2. 根节点的识别可能不准确
3. `traceIdToRootNodeMap` 可能为空

### 原因

如果虚拟父节点没有被正确创建或识别为根节点：
```
建图后:
  只有子节点 PROC_001 (入度=0, 有parentGuid)
  
错误识别:
  brokenNodes: [PROC_001]  ❌ 其实应该创建虚拟父节点
  traceIdToRootNodeMap: {}  ❌ 空的
  
后续:
  创建 EXPLORE_ROOT_TRACE_001
  但这不应该是断链，应该是有虚拟父节点！
```

### 解决方案

确保在建图阶段：
1. ✅ 为有parentGuid的日志创建虚拟父节点
2. ✅ 虚拟父节点被识别为根节点
3. ✅ 建立 `traceId → 虚拟父节点` 的映射

代码检查：
```java
// ProcessChainGraphBuilder.buildGraph()

if (parentGuid != null && !parentGuid.isEmpty()) {
    // ✅ 必须创建虚拟父节点
    if (!graph.hasNode(actualParentNodeId)) {
        GraphNode virtualParent = createVirtualParentNode(rawLog, actualParentNodeId);
        virtualParents.put(actualParentNodeId, virtualParent);
    }
    
    // ✅ 创建边
    graph.addEdge(actualParentNodeId, childGuid);
}

// 后续必须添加虚拟父节点到图中
for (GraphNode virtualParent : virtualParents.values()) {
    if (!graph.hasNode(virtualParent.getNodeId())) {
        graph.addNode(virtualParent);  // ✅ 必须添加
    }
}
```

---

## ✅ 验证清单

### 有真实根节点场景

- [ ] `rootNodes` 包含根节点
- [ ] `brokenNodes` 为空
- [ ] `traceIdToRootNodeMap` 不为空
- [ ] 没有创建EXPLORE节点

### 有断链节点场景

- [ ] `rootNodes` 为空或不完整
- [ ] `brokenNodes` 包含断链节点
- [ ] `traceIdToRootNodeMap` 初始为空
- [ ] 创建了EXPLORE节点
- [ ] EXPLORE节点被添加到 `traceIdToRootNodeMap`
- [ ] 创建了 EXPLORE → 断链节点 的边

### 有虚拟父节点场景

- [ ] 虚拟父节点被创建并添加到图中
- [ ] 虚拟父节点被识别为根节点
- [ ] `traceIdToRootNodeMap` 包含 traceId → 虚拟父节点
- [ ] 没有创建EXPLORE节点

---

## 📝 调试日志

### 正常情况（有根节点）

```
【图分析】根节点数=1, 断链节点数=0, traceId映射数=1
【图分析】traceIdToRootNodeMap: {TRACE_001=ROOT_NODE_ID}
【映射检查】✅ traceIdToRootNodeMap: {TRACE_001=ROOT_NODE_ID}
```

### 断链情况（需要EXPLORE）

```
【图分析】根节点数=0, 断链节点数=1, traceId映射数=0
【图分析】⚠️ 检测到断链节点，但traceIdToRootNodeMap为空，将在后续创建EXPLORE节点
【图分析】断链节点列表: [PROC_001]
【图分析】brokenNodeToTraceId: {PROC_001=TRACE_001}

... 后续 ...

【进程链生成】-> 创建独立 Explore 节点: traceId=TRACE_001 -> nodeId=EXPLORE_ROOT_TRACE_001
【映射检查】✅ traceIdToRootNodeMap: {TRACE_001=EXPLORE_ROOT_TRACE_001}
```

---

**版本**：v1.0  
**日期**：2025-11-20  
**状态**：✅ 逻辑正确，需要验证虚拟父节点创建

