# CoreLogicTest 测试用例更新说明

## 更新时间
2025-01-XX

## 更新原因
代码逻辑已优化为：**所有 traceId（无论单个还是多个）在没有真实根节点时，都创建独立的 `EXPLORE_ROOT_{traceId}` 虚拟根节点**。

之前的测试用例期望单个 traceId 场景下创建通用的 `EXPLORE_ROOT` 节点，这与当前代码逻辑不一致。

## 更新内容

### 1. 测试2：`test02_SingleTraceId_NoRootNode_CreateExplore`

**修改前：**
```java
ProcessNode rootNode = getRootNode(result);
assertEquals("应该创建EXPLORE_ROOT", "EXPLORE_ROOT", rootNode.getNodeId());
```

**修改后：**
```java
ProcessNode rootNode = getRootNode(result);
String expectedExploreId = "EXPLORE_ROOT_" + traceId;
assertEquals("应该创建EXPLORE_ROOT_" + traceId, expectedExploreId, rootNode.getNodeId());
```

**原因：** 单个 traceId 无真实根节点时，应创建 `EXPLORE_ROOT_TRACE_001` 而不是 `EXPLORE_ROOT`。

---

### 2. 测试4：`test04_MultipleBrokenChains_SingleExplore`

**修改前：**
```java
ProcessNode rootNode = getRootNode(result);
assertEquals("应该是EXPLORE_ROOT", "EXPLORE_ROOT", rootNode.getNodeId());

long exploreEdges = result.getEdges().stream()
    .filter(edge -> "EXPLORE_ROOT".equals(edge.getSource()))
    .count();
```

**修改后：**
```java
ProcessNode rootNode = getRootNode(result);
String expectedExploreId = "EXPLORE_ROOT_" + traceId;
assertEquals("应该是EXPLORE_ROOT_" + traceId, expectedExploreId, rootNode.getNodeId());

long exploreEdges = result.getEdges().stream()
    .filter(edge -> expectedExploreId.equals(edge.getSource()))
    .count();
```

**原因：** 多个断链统一连接到同一个 traceId 的 `EXPLORE_ROOT_TRACE_001` 节点，而不是通用的 `EXPLORE_ROOT`。

---

## 设计决策

### 为什么选择统一使用 `EXPLORE_ROOT_{traceId}` 格式？

#### 优点：
1. **一致性**：无论单个还是多个 traceId，逻辑统一，易于理解和维护
2. **可扩展性**：单 traceId 场景如果将来扩展到多 traceId，不需要修改逻辑
3. **桥接边支持**：`createBridgeEdges` 方法依赖 `traceIdToRootNodeMap`，需要明确的 `traceId -> rootNodeId` 映射
4. **避免冲突**：多 traceId 场景下，每个 traceId 都有独立的 EXPLORE 节点，避免混淆

#### 对比方案（已弃用）：
- **方案B**：单 traceId 用 `EXPLORE_ROOT`，多 traceId 用 `EXPLORE_ROOT_{traceId}`
  - 缺点：逻辑复杂，需要判断 traceId 数量
  - 缺点：桥接边创建逻辑需要特殊处理
  - 缺点：不一致性可能导致维护困难

---

## 相关代码变更

### ProcessChainBuilder.java
- `addExploreNodesForBrokenChains` 方法：为每个没有真实根节点的 traceId 创建独立的 `EXPLORE_ROOT_{traceId}` 节点
- `traceIdToRootNodeMap`：记录每个 traceId 到其根节点（真实或虚拟）的映射

### ProcessChainServiceImpl.java
- `createBridgeEdges` 方法：使用 `hostToTraceId` 和 `traceIdToRootNodeMap` 创建桥接边

### IncidentProcessChain.java
- 新增 `traceIdToRootNodeMap` 字段，用于存储 traceId 到根节点的映射

---

## 测试覆盖

### 已更新的测试文件：
1. ✅ `CoreLogicTest.java` - 核心逻辑测试（本次更新）
2. ✅ `ProcessChainIntegrationTest.java` - 集成测试（之前已更新）
3. ✅ `SpringBootProcessChainTest.java` - Spring Boot 集成测试（无需更新）
4. ✅ `ProcessChainMergeTest.java` - 合并测试（无需更新）
5. ✅ `ProcessChainPrunerTest.java` - 裁剪测试（无需更新）

### 测试场景覆盖：
- ✅ 单个 traceId，有真实根节点
- ✅ 单个 traceId，无真实根节点（创建 EXPLORE_ROOT_{traceId}）
- ✅ 多个 traceId，都有真实根节点
- ✅ 多个 traceId，都没有真实根节点（创建多个独立 EXPLORE 节点）
- ✅ 多个 traceId，部分有根节点，部分没有（混合场景）
- ✅ 多个断链统一连接到同一个 EXPLORE_ROOT_{traceId}

---

## 验证方法

运行以下命令验证所有测试通过：

```bash
cd demo
mvn test -Dtest=CoreLogicTest
mvn test -Dtest=ProcessChainIntegrationTest
```

预期结果：所有测试用例通过 ✅

---

## 总结

本次更新确保了测试用例与代码逻辑的一致性，采用统一的 `EXPLORE_ROOT_{traceId}` 命名规则，提高了代码的可维护性和可扩展性。

所有测试文件已检查完毕，无其他需要更新的测试用例。

