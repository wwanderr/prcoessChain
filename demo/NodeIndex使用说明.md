# NodeIndex 使用说明文档

## 📋 概述

`NodeIndex` 是一个多维度索引数据结构，用于优化进程链构建过程中的节点查找性能。

---

## 🎯 设计目标

### 核心理念

**空间换时间**：通过建立多个索引结构，将节点查找的时间复杂度从 **O(N)** 降低到 **O(1)**。

### 设计原则

1. **自动维护**：添加/删除/更新节点时，自动维护所有索引的一致性
2. **类型安全**：通过不可变集合防止外部修改
3. **统一管理**：替代原来的多个独立集合（`rootNodes`、`brokenNodes` 等）

---

## 📊 数据结构详解

### 1. 主索引 - `nodesByGuid`

```java
private final Map<String, ChainBuilderNode> nodesByGuid;
```

#### 作用
根据进程 GUID 快速定位节点（最常用的查找方式）

#### 使用场景
1. `traverseUpward()` 中根据 `processGuid` 查找节点
2. 构建边时，根据 `source`/`target` `processGuid` 查找节点
3. 检查节点是否已存在

#### 性能
- **时间复杂度**：O(1)
- **空间复杂度**：O(N)，N 为节点总数

#### 示例
```java
ChainBuilderNode node = nodeIndex.getByGuid("PROC-12345");
if (node != null) {
    // 处理节点
}
```

---

### 2. traceId 索引 - `nodesByTraceId`

```java
private final Map<String, List<ChainBuilderNode>> nodesByTraceId;
```

#### 作用
根据 `traceId` 快速获取该溯源链的所有节点

#### 使用场景
1. 多 `traceId` 场景下，需要按 `traceId` 分组处理节点
2. 统计某个 `traceId` 的节点数量
3. 为某个 `traceId` 创建 `EXPLORE_ROOT` 节点时，需要知道该 `traceId` 有哪些节点

#### 性能
- **时间复杂度**：O(1) 查找，O(M) 遍历（M 为该 `traceId` 的节点数）
- **空间复杂度**：O(N)

#### 示例
```java
List<ChainBuilderNode> nodes = nodeIndex.getByTraceId("TRACE-001");
System.out.println("TRACE-001 有 " + nodes.size() + " 个节点");
```

#### 注意事项
- 一个节点只属于一个 `traceId`
- 如果 `traceId` 不存在，返回空列表（不是 `null`）

---

### 3. hostAddress 索引 - `nodesByHost`

```java
private final Map<String, List<ChainBuilderNode>> nodesByHost;
```

#### 作用
根据主机 IP 地址快速获取该主机上的所有节点

#### 使用场景
1. 多 IP 场景下，需要按主机分组处理节点
2. 统计某个主机的节点数量
3. 网端桥接时，根据 victim IP 查找端侧节点

#### 性能
- **时间复杂度**：O(1) 查找，O(M) 遍历（M 为该主机的节点数）
- **空间复杂度**：O(N)

#### 示例
```java
List<ChainBuilderNode> nodes = nodeIndex.getByHost("192.168.1.100");
for (ChainBuilderNode node : nodes) {
    System.out.println("主机 192.168.1.100 上的进程: " + node.getProcessName());
}
```

#### 注意事项
- 一个节点只属于一个主机
- 如果主机不存在，返回空列表（不是 `null`）

---

### 4. 根节点索引 - `rootNodes`

```java
private final Set<ChainBuilderNode> rootNodes;
```

#### 作用
快速获取所有根节点（进程链的起点）

#### 使用场景
1. 判断是否找到了真实根节点（`foundRootNode`）
2. 创建 `EXPLORE_ROOT` 节点时，检查是否已有真实根节点
3. 统计根节点数量
4. 遍历所有根节点进行处理

#### 性能
- **时间复杂度**：O(1) 获取集合，O(K) 遍历（K 为根节点数）
- **空间复杂度**：O(K)

#### 判断条件
```java
node.getIsRoot() == true
```

#### 示例
```java
Set<ChainBuilderNode> rootNodes = nodeIndex.getRootNodes();
if (rootNodes.isEmpty()) {
    System.out.println("没有找到真实根节点，需要创建 EXPLORE_ROOT");
} else {
    System.out.println("找到 " + rootNodes.size() + " 个根节点");
}
```

#### 注意事项
- 正常情况下，一个 `traceId` 只有一个真实根节点
- 如果没有真实根节点，会创建 `EXPLORE_ROOT` 虚拟根节点
- 返回的是不可变集合，不能修改

---

### 5. 断链节点索引 - `brokenNodes`

```java
private final Set<ChainBuilderNode> brokenNodes;
```

#### 作用
快速获取所有断链节点（找不到父节点的最顶端节点）

#### 使用场景
1. 判断是否存在断链（需要创建 `EXPLORE_ROOT`）
2. 为断链节点创建到 `EXPLORE_ROOT` 的边
3. 统计断链节点数量
4. 遍历所有断链节点进行处理

#### 性能
- **时间复杂度**：O(1) 获取集合，O(K) 遍历（K 为断链节点数）
- **空间复杂度**：O(K)

#### 判断条件
```java
node.getIsBroken() == true
```

#### 断链定义
- 当前节点不是根节点（`processGuid` 不在 `traceIds` 中）
- 且父节点的日志不存在于原始日志中

#### 示例
```java
Set<ChainBuilderNode> brokenNodes = nodeIndex.getBrokenNodes();
if (!brokenNodes.isEmpty()) {
    System.out.println("发现 " + brokenNodes.size() + " 个断链节点");
    for (ChainBuilderNode brokenNode : brokenNodes) {
        String traceId = brokenNode.getTraceId();
        String exploreNodeId = "EXPLORE_ROOT_" + traceId;
        // 创建断链节点到 EXPLORE_ROOT 的边
        createEdge(brokenNode.getProcessGuid(), exploreNodeId);
    }
}
```

#### 处理方式
为每个断链节点创建到对应 `EXPLORE_ROOT_{traceId}` 的边

---

### 6. 告警节点索引 - `alarmNodes`

```java
private final Set<ChainBuilderNode> alarmNodes;
```

#### 作用
快速获取所有包含告警的节点

#### 使用场景
1. 统计告警节点数量
2. 遍历所有告警节点进行特殊处理（如优先级标记）
3. 智能裁剪时，保护告警节点不被删除
4. 网端关联时，标记关联的告警节点

#### 性能
- **时间复杂度**：O(1) 获取集合，O(K) 遍历（K 为告警节点数）
- **空间复杂度**：O(K)

#### 判断条件
```java
node.getIsAlarm() == true
```

#### 示例
```java
Set<ChainBuilderNode> alarmNodes = nodeIndex.getAlarmNodes();
System.out.println("共有 " + alarmNodes.size() + " 个告警节点");

for (ChainBuilderNode alarmNode : alarmNodes) {
    // 告警节点在进程链中具有最高优先级
    alarmNode.setImportance(Integer.MAX_VALUE);
}
```

#### 注意事项
- 一个节点可能包含多个告警（同一个进程触发多次告警）
- 告警节点在进程链中具有最高优先级，不会被裁剪

---

## 🔧 核心方法详解

### 1. 添加节点 - `addNode()`

```java
public void addNode(ChainBuilderNode node)
```

#### 功能
自动根据节点属性建立多维度索引，一次添加，多维索引

#### 使用场景
1. `ProcessChainBuilder.buildProcessChain()` 中，将所有节点添加到索引
2. 创建 `EXPLORE_ROOT` 虚拟节点后，将其添加到索引

#### 自动索引维护
- 如果节点有 `processGuid` → 添加到主索引
- 如果节点有 `traceId` → 添加到 `traceId` 索引
- 如果节点有 `hostAddress` → 添加到 `hostAddress` 索引
- 如果节点 `isRoot=true` → 添加到根节点索引
- 如果节点 `isBroken=true` → 添加到断链节点索引
- 如果节点 `isAlarm=true` → 添加到告警节点索引

#### 示例
```java
ChainBuilderNode node = new ChainBuilderNode("PROC-12345");
node.setTraceId("TRACE-001");
node.setHostAddress("192.168.1.100");
node.setIsRoot(true);

nodeIndex.addNode(node);  // 自动添加到所有相关索引
```

#### 注意事项
- 如果 `processGuid` 已存在，会覆盖旧节点
- 节点属性为 `null` 时，不会添加到对应的索引

---

### 2. 更新节点 - `updateNode()`

```java
public void updateNode(ChainBuilderNode node)
```

#### 功能
当节点的属性发生变化时（如 `isRoot`、`isBroken` 等），重新建立索引

#### 使用场景
1. `traverseUpward()` 中，发现节点是根节点，设置 `isRoot=true` 后更新索引
2. `traverseUpward()` 中，发现节点是断链节点，设置 `isBroken=true` 后更新索引
3. 节点的 `traceId` 或 `hostAddress` 发生变化时

#### 实现原理
先移除旧索引（基于旧属性），再添加新索引（基于新属性）

#### 示例
```java
ChainBuilderNode node = nodeIndex.getByGuid("PROC-12345");
if (node != null) {
    // 修改节点属性
    node.setIsRoot(true);
    
    // ✅ 必须调用 updateNode 更新索引
    nodeIndex.updateNode(node);
}
```

#### 注意事项
- **必须**在修改节点属性后调用此方法，否则索引会不一致
- 性能开销：O(1) 删除 + O(1) 添加 = O(1)

---

### 3. 移除节点 - `removeNode()`

```java
public void removeNode(String processGuid)
```

#### 功能
从所有索引中移除指定的节点，保持索引一致性

#### 使用场景
1. 智能裁剪时，删除低优先级节点
2. 更新节点时，先移除旧索引
3. 清理无效节点

#### 自动清理
- 从主索引中移除
- 从 `traceId` 索引中移除
- 从 `hostAddress` 索引中移除
- 从根节点索引中移除
- 从断链节点索引中移除
- 从告警节点索引中移除

#### 示例
```java
// 智能裁剪时，删除低优先级节点
if (node.getImportance() < threshold) {
    nodeIndex.removeNode(node.getProcessGuid());
}
```

#### 注意事项
- 如果索引列表为空，会自动清理该索引项（避免内存泄漏）
- 如果 `processGuid` 不存在，不会抛出异常，静默返回

---

## 📈 性能对比

### 原方案 vs 新方案

| 操作 | 原方案（遍历） | 新方案（索引） | 性能提升 |
|------|---------------|---------------|---------|
| 按 processGuid 查找节点 | O(N) | O(1) | **N 倍** |
| 按 traceId 查找所有节点 | O(N) | O(1) | **N 倍** |
| 按 hostAddress 查找所有节点 | O(N) | O(1) | **N 倍** |
| 获取所有根节点 | O(N) | O(1) | **N 倍** |
| 获取所有断链节点 | O(N) | O(1) | **N 倍** |
| 获取所有告警节点 | O(N) | O(1) | **N 倍** |

### 实际场景性能提升

假设进程链有 **1000 个节点**：

| 操作 | 原方案 | 新方案 | 提升 |
|------|--------|--------|------|
| 查找单个节点 | 遍历 1000 次 | 直接查找 1 次 | **1000 倍** |
| 查找 10 次节点 | 遍历 10000 次 | 直接查找 10 次 | **1000 倍** |
| 获取根节点 | 遍历 1000 次 | 直接获取 | **1000 倍** |

---

## 💡 使用示例

### 示例 1：构建进程链时使用 NodeIndex

```java
public ProcessChainResult buildProcessChain(
        List<RawAlarm> alarms, 
        List<RawLog> logs, 
        Set<String> traceIds) {
    
    // 1. 创建 NodeIndex
    NodeIndex nodeIndex = new NodeIndex();
    
    // 2. 将所有节点添加到索引
    for (RawLog log : logs) {
        ChainBuilderNode node = new ChainBuilderNode(log.getProcessGuid());
        node.setTraceId(log.getTraceId());
        node.setHostAddress(log.getHostAddress());
        node.addLog(log);
        
        nodeIndex.addNode(node);
    }
    
    // 3. 添加告警到节点
    for (RawAlarm alarm : alarms) {
        ChainBuilderNode node = nodeIndex.getByGuid(alarm.getProcessGuid());
        if (node != null) {
            node.addAlarm(alarm);
            node.setIsAlarm(true);
            nodeIndex.updateNode(node);  // ✅ 更新索引
        }
    }
    
    // 4. 向上遍历，标记根节点和断链节点
    for (RawAlarm alarm : alarms) {
        traverseUpward(alarm.getProcessGuid(), nodeIndex, traceIds);
    }
    
    // 5. 检查是否需要创建 EXPLORE_ROOT
    if (nodeIndex.getRootNodes().isEmpty()) {
        // 没有真实根节点，为每个 traceId 创建 EXPLORE_ROOT
        for (String traceId : nodeIndex.getAllTraceIds()) {
            ChainBuilderNode exploreNode = createExploreNode(traceId);
            nodeIndex.addNode(exploreNode);
        }
    }
    
    // 6. 为断链节点创建到 EXPLORE_ROOT 的边
    for (ChainBuilderNode brokenNode : nodeIndex.getBrokenNodes()) {
        String traceId = brokenNode.getTraceId();
        String exploreNodeId = "EXPLORE_ROOT_" + traceId;
        createEdge(brokenNode.getProcessGuid(), exploreNodeId);
    }
    
    return buildResult(nodeIndex);
}
```

---

### 示例 2：向上遍历时使用 NodeIndex

```java
private void traverseUpward(
        String currentProcessGuid, 
        NodeIndex nodeIndex,
        Set<String> traceIds) {
    
    // 1. 从索引中快速查找当前节点 - O(1)
    ChainBuilderNode currentNode = nodeIndex.getByGuid(currentProcessGuid);
    if (currentNode == null) {
        return;
    }
    
    // 2. 检查是否是根节点
    if (traceIds.contains(currentProcessGuid)) {
        currentNode.setIsRoot(true);
        nodeIndex.updateNode(currentNode);  // ✅ 更新索引
        return;
    }
    
    // 3. 查找父节点
    String parentProcessGuid = currentNode.getParentProcessGuid();
    ChainBuilderNode parentNode = nodeIndex.getByGuid(parentProcessGuid);
    
    if (parentNode == null) {
        // 父节点不存在，标记为断链
        currentNode.setIsBroken(true);
        nodeIndex.updateNode(currentNode);  // ✅ 更新索引
        return;
    }
    
    // 4. 递归向上遍历
    traverseUpward(parentProcessGuid, nodeIndex, traceIds);
}
```

---

### 示例 3：智能裁剪时使用 NodeIndex

```java
public void pruneNodes(NodeIndex nodeIndex, int maxNodeCount) {
    if (nodeIndex.size() <= maxNodeCount) {
        return;  // 不需要裁剪
    }
    
    // 1. 计算每个节点的重要性
    for (ChainBuilderNode node : nodeIndex.getAllNodes()) {
        int importance = calculateImportance(node);
        node.setImportance(importance);
    }
    
    // 2. 保护告警节点（最高优先级）
    for (ChainBuilderNode alarmNode : nodeIndex.getAlarmNodes()) {
        alarmNode.setImportance(Integer.MAX_VALUE);
    }
    
    // 3. 保护根节点
    for (ChainBuilderNode rootNode : nodeIndex.getRootNodes()) {
        rootNode.setImportance(Math.max(rootNode.getImportance(), 1000));
    }
    
    // 4. 按重要性排序，删除低优先级节点
    List<ChainBuilderNode> sortedNodes = new ArrayList<>(nodeIndex.getAllNodes());
    sortedNodes.sort(Comparator.comparingInt(ChainBuilderNode::getImportance));
    
    int nodesToRemove = nodeIndex.size() - maxNodeCount;
    for (int i = 0; i < nodesToRemove; i++) {
        ChainBuilderNode node = sortedNodes.get(i);
        nodeIndex.removeNode(node.getProcessGuid());  // ✅ 从索引中移除
    }
}
```

---

### 示例 4：多 traceId 场景使用 NodeIndex

```java
public void processMultipleTraceIds(NodeIndex nodeIndex) {
    // 1. 获取所有 traceId
    Set<String> allTraceIds = nodeIndex.getAllTraceIds();
    System.out.println("共有 " + allTraceIds.size() + " 个 traceId");
    
    // 2. 按 traceId 分组处理
    for (String traceId : allTraceIds) {
        List<ChainBuilderNode> nodes = nodeIndex.getByTraceId(traceId);
        System.out.println("traceId=" + traceId + " 有 " + nodes.size() + " 个节点");
        
        // 3. 检查该 traceId 是否有真实根节点
        boolean hasRealRoot = nodes.stream()
            .anyMatch(node -> Boolean.TRUE.equals(node.getIsRoot()));
        
        if (!hasRealRoot) {
            // 4. 没有真实根节点，创建 EXPLORE_ROOT
            ChainBuilderNode exploreNode = new ChainBuilderNode("EXPLORE_ROOT_" + traceId);
            exploreNode.setTraceId(traceId);
            exploreNode.setIsRoot(true);
            nodeIndex.addNode(exploreNode);
            
            System.out.println("为 traceId=" + traceId + " 创建了 EXPLORE_ROOT 节点");
        }
    }
}
```

---

## ⚠️ 注意事项

### 1. 索引一致性

**问题**：修改节点属性后忘记更新索引

```java
// ❌ 错误示例
ChainBuilderNode node = nodeIndex.getByGuid("PROC-12345");
node.setIsRoot(true);  // 修改了属性
// 忘记调用 nodeIndex.updateNode(node);
// 导致 rootNodes 索引不一致！
```

**解决方案**：修改节点属性后，必须调用 `updateNode()`

```java
// ✅ 正确示例
ChainBuilderNode node = nodeIndex.getByGuid("PROC-12345");
node.setIsRoot(true);
nodeIndex.updateNode(node);  // ✅ 更新索引
```

---

### 2. 不可变集合

**问题**：尝试修改返回的集合

```java
// ❌ 错误示例
Set<ChainBuilderNode> rootNodes = nodeIndex.getRootNodes();
rootNodes.add(newNode);  // 抛出 UnsupportedOperationException
```

**解决方案**：返回的集合是不可变的，不能直接修改

```java
// ✅ 正确示例
ChainBuilderNode newNode = new ChainBuilderNode("PROC-12345");
newNode.setIsRoot(true);
nodeIndex.addNode(newNode);  // 通过 addNode 添加
```

---

### 3. 空值处理

**问题**：没有检查返回值是否为 `null`

```java
// ❌ 错误示例
ChainBuilderNode node = nodeIndex.getByGuid("PROC-12345");
String processName = node.getProcessName();  // 可能抛出 NullPointerException
```

**解决方案**：始终检查返回值

```java
// ✅ 正确示例
ChainBuilderNode node = nodeIndex.getByGuid("PROC-12345");
if (node != null) {
    String processName = node.getProcessName();
}
```

---

### 4. 空列表 vs null

**问题**：混淆空列表和 `null`

```java
// ❌ 错误示例
List<ChainBuilderNode> nodes = nodeIndex.getByTraceId("TRACE-001");
if (nodes == null) {  // 永远不会为 null
    // ...
}
```

**解决方案**：返回的是空列表，不是 `null`

```java
// ✅ 正确示例
List<ChainBuilderNode> nodes = nodeIndex.getByTraceId("TRACE-001");
if (nodes.isEmpty()) {  // 检查是否为空
    System.out.println("没有找到节点");
}
```

---

## 🎯 最佳实践

### 1. 统一使用 NodeIndex

**不推荐**：混用 `NodeIndex` 和独立集合

```java
// ❌ 不推荐
NodeIndex nodeIndex = new NodeIndex();
Set<String> rootNodes = new HashSet<>();  // 独立维护
Set<String> brokenNodes = new HashSet<>();  // 独立维护
// 容易导致数据不一致
```

**推荐**：只使用 `NodeIndex`

```java
// ✅ 推荐
NodeIndex nodeIndex = new NodeIndex();
// 所有节点信息都通过 nodeIndex 管理
```

---

### 2. 及时更新索引

**不推荐**：批量修改后一次性更新

```java
// ❌ 不推荐
for (ChainBuilderNode node : nodes) {
    node.setIsRoot(true);
}
// 批量更新
for (ChainBuilderNode node : nodes) {
    nodeIndex.updateNode(node);
}
```

**推荐**：修改后立即更新

```java
// ✅ 推荐
for (ChainBuilderNode node : nodes) {
    node.setIsRoot(true);
    nodeIndex.updateNode(node);  // 立即更新
}
```

---

### 3. 使用不可变集合的优势

```java
// ✅ 推荐：利用不可变集合的线程安全特性
Set<ChainBuilderNode> rootNodes = nodeIndex.getRootNodes();
// 可以安全地在多线程环境中读取
// 不用担心其他线程修改
```

---

## 📚 总结

### 核心优势

1. **性能提升**：查询时间复杂度从 O(N) 降低到 O(1)
2. **自动维护**：添加/删除/更新节点时，自动维护所有索引
3. **类型安全**：通过不可变集合防止外部修改
4. **统一管理**：替代多个独立集合，简化代码

### 适用场景

- 进程链构建
- 节点查找和分类
- 智能裁剪
- 多 traceId 处理
- 网端桥接

### 关键要点

1. 修改节点属性后，必须调用 `updateNode()`
2. 返回的集合是不可变的，不能直接修改
3. 查询方法返回空列表，不是 `null`
4. 统一使用 `NodeIndex`，不要混用独立集合

---

**NodeIndex 是进程链构建的核心优化，正确使用可以显著提升性能！** 🚀

