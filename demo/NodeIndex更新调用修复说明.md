# NodeIndex.updateNode() 调用修复说明

## 问题发现

在代码审查中发现 `NodeIndex.updateNode()` 方法在项目中没有被调用，导致节点索引无法正确更新。

## 问题分析

在 `ProcessChainBuilder.java` 中，有多处修改了节点的 `isRoot` 和 `isBroken` 属性，但都**没有调用 `nodeIndex.updateNode()`** 来更新索引。这会导致索引数据不一致。

### 发现的问题位置

1. **第293行** - 设置告警节点为根节点
2. **第316行** - 设置日志节点为根节点
3. **第367行** - 在 `traverseUpward()` 中找到根节点
4. **第389行** - 父节点为空时的根节点
5. **第401行** - 设置断链节点

## 修复方案

### 1. 添加 NodeIndex 实例

在 `ProcessChainBuilder` 类中添加 `NodeIndex` 成员变量：

```java
// 节点索引（多维度查询）
private NodeIndex nodeIndex;

public ProcessChainBuilder() {
    // ... 其他初始化 ...
    this.nodeIndex = new NodeIndex();
}
```

### 2. 在修改节点属性后调用 updateNode()

在所有设置 `isRoot` 或 `isBroken` 的地方，添加 `nodeIndex.updateNode()` 调用：

#### 修改点1: 告警节点是根节点
```java
ChainBuilderNode node = nodeMap.get(processGuid);
if (node != null) {
    node.setIsRoot(true);
    nodeIndex.updateNode(node);  // ✅ 新增
}
```

#### 修改点2: 日志节点是根节点
```java
ChainBuilderNode logNode = nodeMap.get(logProcessGuid);
if (logNode != null) {
    logNode.setIsRoot(true);
    nodeIndex.updateNode(logNode);  // ✅ 新增
}
```

#### 修改点3: 向上遍历找到根节点
```java
currentNode.setIsRoot(true);
nodeIndex.updateNode(currentNode);  // ✅ 新增
```

#### 修改点4: 父节点为空的根节点
```java
currentNode.setIsRoot(true);
nodeIndex.updateNode(currentNode);  // ✅ 新增
```

#### 修改点5: 断链节点
```java
currentNode.setIsBroken(true);
nodeIndex.updateNode(currentNode);  // ✅ 新增
```

## 关于 ProcessChainExtensionUtil

`ProcessChainExtensionUtil` 工具类中也有修改 `isRoot` 的代码，但**不需要调用 `updateNode()`**，原因如下：

1. **不同阶段**: `NodeIndex` 只在进程链构建阶段（`ProcessChainBuilder`）使用
2. **不同数据结构**: 扩展工具类操作的是已转换的 `ProcessNode`（最终输出），而不是构建阶段的 `ChainBuilderNode`
3. **独立工具**: 扩展是在构建完成后的后处理步骤，不需要索引支持

## 修复效果

修复后，`NodeIndex` 的索引数据会实时更新：

- `rootNodes`: 所有根节点的索引
- `brokenNodes`: 所有断链节点的索引
- `nodesByProcessGuid`: 按 processGuid 索引
- `nodesByTraceId`: 按 traceId 索引
- `nodesByHost`: 按 hostAddress 索引

这确保了索引查询的正确性和一致性。

## 测试验证

所有现有测试用例均通过，未发现回归问题。

## 相关文件

- `demo/src/main/java/com/security/processchain/service/ProcessChainBuilder.java`
- `demo/src/main/java/com/security/processchain/service/NodeIndex.java`
- `demo/src/main/java/com/security/processchain/util/ProcessChainExtensionUtil.java`

## 修复时间

2025-10-27


