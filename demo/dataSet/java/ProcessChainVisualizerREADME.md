# ProcessChainVisualizer - 进程链可视化工具

## 功能说明

这个工具可以读取包含 `IncidentProcessChain` 数据结构的 JSON 文件，并生成可视化的链式关系图。

## 使用方法

### 1. 修改输入文件路径

在 `ProcessChainVisualizer.java` 文件中，修改以下常量为你的实际文件路径：

```java
private static final String INPUT_FILE_PATH = "C:\\Users\\18395\\Desktop\\demo\\demo\\dataSet\\output\\chain_result.json";
```

### 2. 编译程序

使用以下命令编译（需要 Jackson 库）：

```bash
# 如果使用 Maven 项目依赖
javac -cp ".;lib/*" ProcessChainVisualizer.java

# 或者如果已安装 Jackson 库
javac -cp ".;jackson-core.jar;jackson-databind.jar;jackson-annotations.jar" ProcessChainVisualizer.java
```

### 3. 运行程序

```bash
# 使用 Maven 项目依赖
java -cp ".;lib/*" ProcessChainVisualizer

# 或者直接运行
java -cp ".;jackson-core.jar;jackson-databind.jar;jackson-annotations.jar" ProcessChainVisualizer
```

### 4. 查看结果

程序会：
1. 在控制台输出可视化的进程链关系图
2. 在输入文件同目录生成 `*_visualization.md` 文件

## 输入数据格式

输入的 JSON 文件应包含以下结构（外层有 `data` 包装）：

```json
{
  "data": {
    "traceIds": ["traceId-001", "traceId-002"],
    "hostAddresses": ["10.50.86.151", "10.50.110.193"],
    "threatSeverity": "HIGH",
    "nodes": [
      {
        "nodeId": "node-001",
        "logType": "PROCESS",
        "nodeThreatSeverity": "HIGH",
        "isChainNode": true,
        "chainNode": {
          "isRoot": true,
          "isAlarm": true,
          "isBroken": false,
          "processEntity": {
            "processName": "cmd.exe",
            "processId": 1234,
            "commandLine": "cmd.exe /c whoami",
            "processUserName": "Administrator",
            "processStartTime": "2025-05-23 15:31:06",
            "processMd5": "abc123..."
          },
          "alarmNodeInfo": {
            "name": "命令执行告警",
            "ruleName": "检测到异常命令执行",
            "ruleType": "/CommandExecution"
          }
        },
        "childrenCount": 2
      }
    ],
    "edges": [
      {
        "source": "parent-node-id",
        "target": "child-node-id",
        "val": "process_create"
      }
    ]
  }
}
```

**注意**: JSON 格式为 `{data: {IncidentProcessChain}}`，外层有一个 `data` 字段包装整个进程链数据。

## 输出示例

程序会生成类似以下格式的可视化图表：

```
## 基本信息

**TraceID(s)**: [traceId-001, traceId-002]
**主机IP(s)**: [10.50.86.151, 10.50.110.193]
**威胁等级**: HIGH
**节点数量**: 12
**边数量**: 11

## 进程链结构

```
└── [ROOT,ALARM] cmd.exe (PID:1234) - Administrator [HIGH]
    ├── whoami.exe (PID:5678) - Administrator [MEDIUM]
    └── net.exe (PID:5679) - Administrator [LOW]
```

## 节点详细信息

### 1. cmd.exe

- **节点ID**: node-001
- **类型**: PROCESS
- **威胁等级**: HIGH
- **是否进程链节点**: true
- **是否根节点**: true
- **是否告警节点**: true
- **进程名**: cmd.exe
- **进程ID**: 1234
- **命令行**: cmd.exe /c whoami
- **用户**: Administrator
- **启动时间**: 2025-05-23 15:31:06
- **告警名称**: 命令执行告警
```

## 依赖库

本程序需要 Jackson 库来解析 JSON：

- jackson-core
- jackson-databind
- jackson-annotations

如果在 Maven 项目中使用，这些依赖已经在 `pom.xml` 中配置。

## 注意事项

1. **路径格式**: Windows 路径需要使用双反斜杠 `\\` 或单斜杠 `/`
2. **JSON 格式**: 确保输入的 JSON 文件格式正确
3. **编码**: 文件默认使用 UTF-8 编码
4. **循环引用**: 程序会自动检测并防止循环引用导致的无限递归

## 故障排除

### 问题：找不到输入文件
- 检查文件路径是否正确
- 确认文件确实存在
- 检查文件权限

### 问题：JSON 解析失败
- 验证 JSON 格式是否正确
- 检查是否有未转义的特殊字符
- 确认数据结构是否符合 IncidentProcessChain 格式

### 问题：未找到根节点
- 检查 edges 中是否有正确的父子关系
- 确认是否有节点的 `isRoot` 标记为 true
- 验证 nodeId 是否唯一且匹配

## 扩展功能

可以根据需要扩展以下功能：
1. 支持多种输出格式（HTML, SVG, DOT 等）
2. 添加节点过滤功能
3. 支持批量处理多个文件
4. 添加统计分析功能

