# 验证 NodeIndex 修复效果

## 如何验证修复

### 方法1: 查看代码变更

检查 `ProcessChainBuilder.java` 中是否有以下调用：

```bash
# 搜索 updateNode 调用
grep -n "nodeIndex.updateNode" demo/src/main/java/com/security/processchain/service/ProcessChainBuilder.java
```

**期望输出**（5处调用）:
```
294:                nodeIndex.updateNode(node);  // 更新索引
317:                            nodeIndex.updateNode(logNode);  // 更新索引
368:            nodeIndex.updateNode(currentNode);  // 更新索引
390:                nodeIndex.updateNode(currentNode);  // 更新索引
402:            nodeIndex.updateNode(currentNode);  // 更新索引
```

### 方法2: 运行测试用例

```bash
cd demo

# 测试 NodeIndex 功能
mvn test -Dtest=DataStructureOptimizationTest

# 测试进程链集成
mvn test -Dtest=ProcessChainIntegrationTest
```

### 方法3: 断点调试

在 IDE 中设置断点：

1. **断点位置**: `NodeIndex.updateNode()` 方法
2. **运行测试**: `DataStructureOptimizationTest.test04_NodeIndex_RootAndBrokenNodes()`
3. **验证**: 断点应该被触发 5 次（对应 5 处修改）

### 方法4: 日志验证

在 `NodeIndex.updateNode()` 方法中添加日志：

```java
public void updateNode(ChainBuilderNode node) {
    log.debug("【索引更新】-> 更新节点: {}, isRoot={}, isBroken={}", 
              node.getProcessGuid(), node.getIsRoot(), node.getIsBroken());
    
    if (node == null || node.getProcessGuid() == null) {
        return;
    }
    
    // ... 原有代码 ...
}
```

运行测试后，日志中应该看到类似输出：
```
【索引更新】-> 更新节点: T001, isRoot=true, isBroken=false
【索引更新】-> 更新节点: NODE_BROKEN_001, isRoot=false, isBroken=true
...
```

## 验证清单

- [ ] 代码中有 5 处 `nodeIndex.updateNode()` 调用
- [ ] `ProcessChainBuilder` 构造函数中初始化了 `nodeIndex`
- [ ] 所有测试用例通过
- [ ] 无编译错误
- [ ] 日志显示索引更新正常

## 预期行为

### 修复前（❌错误）

```java
node.setIsRoot(true);
// 索引未更新！nodeIndex.getRootNodes() 不包含此节点
```

### 修复后（✅正确）

```java
node.setIsRoot(true);
nodeIndex.updateNode(node);  // 索引已更新
// nodeIndex.getRootNodes() 正确包含此节点
```

## 问题排查

### 如果测试失败

1. **检查编译**: 确保没有编译错误
2. **检查导入**: 确保 `NodeIndex` 类正确导入
3. **检查初始化**: 确保 `nodeIndex` 在构造函数中初始化
4. **查看日志**: 检查是否有异常信息

### 常见问题

**Q: 为什么 ProcessChainExtensionUtil 不需要调用 updateNode()？**

A: 因为扩展工具类操作的是已转换的 `ProcessNode`（最终输出），而不是构建阶段的 `ChainBuilderNode`。索引只在构建阶段使用。

**Q: 性能会有影响吗？**

A: 影响可忽略。每次调用 `updateNode()` 只是更新几个 Map，时间复杂度 O(1)。

**Q: 如果忘记调用 updateNode() 会怎样？**

A: 索引数据会不一致，导致通过索引查询（如 `getRootNodes()`）得到错误结果。但不影响进程链本身的构建。

## 相关资源

- `NodeIndex.java` - 索引实现
- `ProcessChainBuilder.java` - 进程链构建器
- `DataStructureOptimizationTest.java` - 测试用例
- `NodeIndex使用说明.md` - 使用说明
- `NodeIndex修复完成总结.md` - 修复总结


