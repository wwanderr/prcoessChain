# Lombok Setter 方法命名规则说明

## 🔍 问题总结

在本次重构中，发现了因为 Lombok 的 setter 命名规则导致的方法调用错误。

---

## 📋 Lombok Setter 命名规则

### 规则：根据字段类型生成不同的方法名

#### 1. 原始类型 `boolean` → `set<FieldName>()`

```java
@Getter
@Setter
public class GraphNode {
    private boolean isRoot;     // 字段名包含 is
    private boolean isBroken;   // 字段名包含 is
    private boolean isAlarm;    // 字段名包含 is
}

// Lombok 生成的方法：
public void setRoot(boolean isRoot) { ... }      // ✅ 去掉 is
public void setBroken(boolean isBroken) { ... }  // ✅ 去掉 is
public void setAlarm(boolean isAlarm) { ... }    // ✅ 去掉 is
```

#### 2. 包装类型 `Boolean` → `setIs<FieldName>()`

```java
@Getter
@Setter
public class ChainBuilderNode {
    private Boolean isRoot;     // 字段名包含 is
    private Boolean isBroken;   // 字段名包含 is
    private Boolean isAlarm;    // 字段名包含 is
}

// Lombok 生成的方法：
public void setIsRoot(Boolean isRoot) { ... }      // ✅ 保留 is
public void setIsBroken(Boolean isBroken) { ... }  // ✅ 保留 is
public void setIsAlarm(Boolean isAlarm) { ... }    // ✅ 保留 is
```

---

## 🐛 本项目中发现的错误

### 错误调用

| 类 | 字段类型 | 错误调用 | 正确调用 |
|---|---------|---------|---------|
| GraphNode | `boolean isRoot` | ❌ `setIsRoot()` | ✅ `setRoot()` |
| GraphNode | `boolean isBroken` | ❌ `setIsBroken()` | ✅ `setBroken()` |
| GraphNode | `boolean isAlarm` | ❌ `setIsAlarm()` | ✅ `setAlarm()` |
| ChainBuilderNode | `Boolean isRoot` | ✅ `setIsRoot()` | - |
| ChainBuilderNode | `Boolean isBroken` | ✅ `setIsBroken()` | - |
| ChainNode | `Boolean isRoot` | ✅ `setIsRoot()` | - |

---

## 🔧 修复的文件和位置

### ProcessChainGraph.java

修复了 **5处** `setIsRoot()` 调用：

1. **第278行**：根节点识别（规则1）
```java
// ❌ 错误
node.setIsRoot(true);

// ✅ 正确
node.setRoot(true);
```

2. **第287行**：虚拟根父节点识别
```java
// ❌ 错误
node.setIsRoot(true);

// ✅ 正确
node.setRoot(true);
```

3. **第300行**：将原根节点的 isRoot 改为 false
```java
// ❌ 错误
oldRootNode.setIsRoot(false);

// ✅ 正确
oldRootNode.setRoot(false);
```

4. **第310行**：processGuid == traceId 的根节点
```java
// ❌ 错误
node.setIsRoot(true);

// ✅ 正确
node.setRoot(true);
```

5. **第343行**：入度为0且无parentGuid的根节点
```java
// ❌ 错误
node.setIsRoot(true);

// ✅ 正确
node.setRoot(true);
```

修复了 **1处** `setIsBroken()` 调用：

6. **第329行**：标记断链节点
```java
// ❌ 错误
node.setIsBroken(true);

// ✅ 正确
node.setBroken(true);
```

---

## 📝 代码示例对比

### 示例1：GraphNode（原始 boolean）

```java
GraphNode node = new GraphNode();

// ❌ 错误的调用（会编译错误）
node.setIsRoot(true);      // 方法不存在！
node.setIsBroken(true);    // 方法不存在！
node.setIsAlarm(true);     // 方法不存在！

// ✅ 正确的调用
node.setRoot(true);
node.setBroken(true);
node.setAlarm(true);

// Getter 仍然保留 is 前缀
boolean isRoot = node.isRoot();
boolean isBroken = node.isBroken();
boolean isAlarm = node.isAlarm();
```

### 示例2：ChainBuilderNode（包装 Boolean）

```java
ChainBuilderNode node = new ChainBuilderNode();

// ✅ 正确的调用
node.setIsRoot(true);
node.setIsBroken(true);
node.setIsAlarm(true);

// Getter
Boolean isRoot = node.getIsRoot();
Boolean isBroken = node.getIsBroken();
Boolean isAlarm = node.getIsAlarm();
```

---

## 🎯 为什么会有这个规则？

### Java Bean 命名规范

Java Bean 规范约定：
- 对于 `boolean` 类型，getter 方法用 `is` 前缀
- 对于 `Boolean` 类型，getter 方法用 `get` 前缀

Lombok 遵循这个规范，并在 setter 中做了对应处理：

```java
// boolean 类型
private boolean isRoot;
public boolean isRoot() { ... }     // getter: is 前缀
public void setRoot(boolean) { ... } // setter: 去掉 is

// Boolean 类型
private Boolean isRoot;
public Boolean getIsRoot() { ... }    // getter: get 前缀 + is
public void setIsRoot(Boolean) { ... } // setter: 保留 is
```

---

## 💡 最佳实践建议

### 1. 统一使用包装类型 Boolean

**优点**：
- setter 方法名更直观（`setIsRoot()` vs `setRoot()`）
- 可以表示 null 状态（三态逻辑）
- 避免 Lombok 的命名混淆

**缺点**：
- 占用更多内存（对象 vs 原始类型）
- 需要处理 null 值

### 2. 或者避免 is 前缀

如果一定要用 `boolean`，避免 `is` 前缀：

```java
@Getter
@Setter
public class GraphNode {
    private boolean root;     // ✅ 不用 isRoot
    private boolean broken;   // ✅ 不用 isBroken
    private boolean alarm;    // ✅ 不用 isAlarm
}

// Lombok 生成：
public void setRoot(boolean root) { ... }
public boolean isRoot() { ... }  // getter 仍然是 isRoot()
```

### 3. 使用 IDE 自动补全

依赖 IDE 的自动补全功能，避免手动输入方法名。

---

## ✅ 验证结果

- 修复文件：`ProcessChainGraph.java`
- 修复方法调用：6处
- Linter 检查：✅ 无错误
- 编译状态：✅ 通过

---

## 🔍 如何避免此类问题

1. **使用 IDE 的代码检查**：会提示方法不存在
2. **编译测试**：编译时会报错
3. **统一代码规范**：团队约定统一使用 `Boolean` 或不用 `is` 前缀
4. **Code Review**：审查时注意 Lombok 生成的方法名


