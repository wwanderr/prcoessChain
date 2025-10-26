# ProcessChainIntegrationTest 修复说明

## 📋 问题描述

在优化 `traceIdToRootNodeMap` 后，`ProcessChainIntegrationTest.java` 中的测试用例报错。

### 错误信息

```
The method getTraceIdToRootNodeMap() is undefined for the type IncidentProcessChain
```

### 错误位置

- Line 516: `result.getTraceIdToRootNodeMap()`
- Line 540: `result.getTraceIdToRootNodeMap().get("T001")`
- Line 542: `result.getTraceIdToRootNodeMap().get("T002")`
- Line 544: `result.getTraceIdToRootNodeMap().get("T003")`
- Line 602: `result.getTraceIdToRootNodeMap()`
- Line 626: `result.getTraceIdToRootNodeMap().get("T001")`
- Line 628: `result.getTraceIdToRootNodeMap().get("T002")`
- Line 630: `result.getTraceIdToRootNodeMap().get("T003")`

---

## 🔍 问题原因

在之前的优化中，我们将 `traceIdToRootNodeMap` 从 `IncidentProcessChain` 数据模型中移除，改为通过 `ProcessChainBuilder.getTraceIdToRootNodeMap()` 方法获取。

但 `ProcessChainIntegrationTest.java` 中的测试用例仍然使用旧的方式从 `IncidentProcessChain` 获取这个映射，导致编译错误。

---

## ✅ 修复方案

### 修改前（错误）

```java
// 执行
ProcessChainBuilder builder = new ProcessChainBuilder();
IncidentProcessChain result = builder.buildIncidentChain(
    alarms,
    logs,
    traceIds,
    associatedEventIds,
    IncidentConverters.NODE_MAPPER,
    IncidentConverters.EDGE_MAPPER
);

// ❌ 错误：从 IncidentProcessChain 获取
assertNotNull(result.getTraceIdToRootNodeMap());
assertEquals("EXPLORE_ROOT_T001", result.getTraceIdToRootNodeMap().get("T001"));
```

### 修改后（正确）

```java
// 执行
ProcessChainBuilder builder = new ProcessChainBuilder();
IncidentProcessChain result = builder.buildIncidentChain(
    alarms,
    logs,
    traceIds,
    associatedEventIds,
    IncidentConverters.NODE_MAPPER,
    IncidentConverters.EDGE_MAPPER
);

// ✅ 正确：从 builder 获取 traceIdToRootNodeMap
Map<String, String> traceIdToRootNodeMap = builder.getTraceIdToRootNodeMap();

// 验证
assertNotNull(traceIdToRootNodeMap);
assertEquals("EXPLORE_ROOT_T001", traceIdToRootNodeMap.get("T001"));
```

---

## 📝 修改详情

### 测试方法 1：`testMultipleTraceIds_AllWithoutRootNodes`

**修改位置**：Line 502-548

**修改内容**：

1. 在 `buildIncidentChain()` 调用后，添加：
   ```java
   // ✅ 优化：从 builder 获取 traceIdToRootNodeMap（不再从 IncidentProcessChain 获取）
   Map<String, String> traceIdToRootNodeMap = builder.getTraceIdToRootNodeMap();
   ```

2. 将所有 `result.getTraceIdToRootNodeMap()` 替换为 `traceIdToRootNodeMap`

**修改前**：
```java
assertNotNull(result.getTraceIdToRootNodeMap(), "traceIdToRootNodeMap 不应为空");
assertEquals("EXPLORE_ROOT_T001", result.getTraceIdToRootNodeMap().get("T001"));
assertEquals("EXPLORE_ROOT_T002", result.getTraceIdToRootNodeMap().get("T002"));
assertEquals("EXPLORE_ROOT_T003", result.getTraceIdToRootNodeMap().get("T003"));
```

**修改后**：
```java
assertNotNull(traceIdToRootNodeMap, "traceIdToRootNodeMap 不应为空");
assertEquals("EXPLORE_ROOT_T001", traceIdToRootNodeMap.get("T001"));
assertEquals("EXPLORE_ROOT_T002", traceIdToRootNodeMap.get("T002"));
assertEquals("EXPLORE_ROOT_T003", traceIdToRootNodeMap.get("T003"));
```

---

### 测试方法 2：`testMixedScenario_SomeWithRootNodes_SomeWithout`

**修改位置**：Line 592-637

**修改内容**：

1. 在 `buildIncidentChain()` 调用后，添加：
   ```java
   // ✅ 优化：从 builder 获取 traceIdToRootNodeMap（不再从 IncidentProcessChain 获取）
   Map<String, String> traceIdToRootNodeMap = builder.getTraceIdToRootNodeMap();
   ```

2. 将所有 `result.getTraceIdToRootNodeMap()` 替换为 `traceIdToRootNodeMap`

**修改前**：
```java
assertNotNull(result.getTraceIdToRootNodeMap());
assertEquals("T001", result.getTraceIdToRootNodeMap().get("T001"));
assertEquals("EXPLORE_ROOT_T002", result.getTraceIdToRootNodeMap().get("T002"));
assertEquals("T003", result.getTraceIdToRootNodeMap().get("T003"));
```

**修改后**：
```java
assertNotNull(traceIdToRootNodeMap);
assertEquals("T001", traceIdToRootNodeMap.get("T001"));
assertEquals("EXPLORE_ROOT_T002", traceIdToRootNodeMap.get("T002"));
assertEquals("T003", traceIdToRootNodeMap.get("T003"));
```

---

## 🎯 修改原则

### 核心原则

**`traceIdToRootNodeMap` 是构建辅助数据，不是业务数据**

- ❌ 不应该从 `IncidentProcessChain` 获取（业务数据模型）
- ✅ 应该从 `ProcessChainBuilder` 获取（构建器）

### 修改模式

在所有使用 `traceIdToRootNodeMap` 的测试中，遵循以下模式：

```java
// 1. 构建进程链
ProcessChainBuilder builder = new ProcessChainBuilder();
IncidentProcessChain result = builder.buildIncidentChain(...);

// 2. 从 builder 获取 traceIdToRootNodeMap
Map<String, String> traceIdToRootNodeMap = builder.getTraceIdToRootNodeMap();

// 3. 使用 traceIdToRootNodeMap 进行验证
assertNotNull(traceIdToRootNodeMap);
assertEquals(expectedValue, traceIdToRootNodeMap.get(key));
```

---

## ✅ 修复结果

### 编译状态

- ✅ 所有编译错误已修复
- ✅ 所有测试用例可以正常编译
- ⚠️ 仅剩 1 个警告（`isMediumSeverity` 方法未使用，不影响功能）

### 测试状态

修改后的测试用例：

1. ✅ `testMultipleTraceIds_AllWithoutRootNodes` - 测试多个 traceId 都没有真实根节点
2. ✅ `testMixedScenario_SomeWithRootNodes_SomeWithout` - 测试混合场景（部分有根节点，部分没有）

---

## 📊 影响范围

### 受影响的文件

- ✅ `demo/src/test/java/com/security/processchain/ProcessChainIntegrationTest.java`

### 不受影响的文件

- ✅ `demo/src/test/java/com/security/processchain/CoreLogicTest.java` - 未使用 `getTraceIdToRootNodeMap()`
- ✅ `demo/src/test/java/com/security/processchain/SpringBootProcessChainTest.java` - 未使用 `getTraceIdToRootNodeMap()`
- ✅ `demo/src/test/java/com/security/processchain/RealWorldAttackScenariosTest.java` - 未使用 `getTraceIdToRootNodeMap()`
- ✅ `demo/src/test/java/com/security/processchain/DataStructureOptimizationTest.java` - 未使用 `getTraceIdToRootNodeMap()`

---

## 🔄 与之前优化的一致性

这次修复与之前的 `traceIdToRootNodeMap` 优化保持一致：

### 主代码优化（已完成）

1. ✅ `ProcessChainBuilder.java` - 添加 `getTraceIdToRootNodeMap()` 方法
2. ✅ `IncidentProcessChain.java` - 删除 `traceIdToRootNodeMap` 字段
3. ✅ `ProcessChainServiceImpl.java` - 通过参数传递 `traceIdToRootNodeMap`

### 测试代码修复（本次完成）

4. ✅ `ProcessChainIntegrationTest.java` - 从 `builder` 获取 `traceIdToRootNodeMap`

---

## 💡 最佳实践

### 测试中使用 traceIdToRootNodeMap 的正确方式

```java
@Test
void testExample() {
    // 1. 准备测试数据
    List<RawAlarm> alarms = ...;
    List<RawLog> logs = ...;
    Set<String> traceIds = ...;
    
    // 2. 构建进程链
    ProcessChainBuilder builder = new ProcessChainBuilder();
    IncidentProcessChain result = builder.buildIncidentChain(
        alarms, logs, traceIds, associatedEventIds,
        IncidentConverters.NODE_MAPPER, IncidentConverters.EDGE_MAPPER
    );
    
    // 3. ✅ 从 builder 获取 traceIdToRootNodeMap
    Map<String, String> traceIdToRootNodeMap = builder.getTraceIdToRootNodeMap();
    
    // 4. 验证业务数据（从 result 获取）
    assertNotNull(result);
    assertNotNull(result.getNodes());
    assertNotNull(result.getEdges());
    
    // 5. 验证辅助数据（从 traceIdToRootNodeMap 获取）
    assertNotNull(traceIdToRootNodeMap);
    assertEquals("EXPLORE_ROOT_T001", traceIdToRootNodeMap.get("T001"));
}
```

### 关键要点

1. **业务数据** → 从 `IncidentProcessChain` 获取
   - `result.getNodes()`
   - `result.getEdges()`
   - `result.getTraceIds()`
   - `result.getHostAddresses()`
   - `result.getThreatSeverity()`

2. **辅助数据** → 从 `ProcessChainBuilder` 获取
   - `builder.getTraceIdToRootNodeMap()`

---

## 📚 相关文档

- `traceIdToRootNodeMap优化说明.md` - 详细的优化说明
- `NodeIndex使用说明.md` - NodeIndex 的使用指南

---

## ✅ 总结

### 问题

`ProcessChainIntegrationTest.java` 中的测试用例使用了已删除的 `IncidentProcessChain.getTraceIdToRootNodeMap()` 方法，导致编译错误。

### 解决方案

修改测试用例，改为从 `ProcessChainBuilder.getTraceIdToRootNodeMap()` 获取映射。

### 结果

- ✅ 所有编译错误已修复
- ✅ 测试代码与主代码的优化保持一致
- ✅ 符合"数据模型只包含业务数据"的设计原则

**修复完成！** 🎉

