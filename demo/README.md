# 进程链生成系统

> 基于SpringBoot 2.x + Elasticsearch的安全事件进程链生成系统

[![Java](https://img.shields.io/badge/Java-1.8-blue.svg)](https://www.oracle.com/java/)
[![SpringBoot](https://img.shields.io/badge/SpringBoot-2.7.18-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-7.17.15-yellow.svg)](https://www.elastic.co/)

## 📖 项目简介

本系统是一个企业级的安全事件进程链生成系统，用于分析和可视化安全告警的进程关系链。系统通过分析EDR告警和原始日志，自动构建完整的进程调用链路，帮助安全分析师快速定位攻击路径和威胁源头。

### 核心特性

- 🚀 **高性能批量查询** - ES批量查询优化，性能提升10-1000倍
- 🛡️ **智能告警选举** - 多维度告警优先级算法
- 🔄 **双向进程追溯** - 向上追溯父进程 + 向下探查子进程
- 🎯 **智能节点裁剪** - 基于重要性评分的节点裁剪机制
- 🔒 **完善异常处理** - 分层异常保护，确保系统稳定性
- 📊 **RESTful API** - 标准的REST接口，易于集成

## 🏗️ 技术架构

```
┌─────────────────────────────────────────────────────────────┐
│                     REST API (Controller)                    │
│                  /api/processchain/generate                  │
│              /api/processchain/batch-generate                │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                Service Layer (服务层)                         │
│  ┌──────────────────────┐  ┌─────────────────────────────┐  │
│  │ProcessChainService   │  │OptimizedESQueryService      │  │
│  │- 流程编排            │  │- 批量告警查询 (MultiSearch)  │  │
│  │- 告警选举            │  │- 批量日志查询 (Terms Query)  │  │
│  │- 日志查询            │  │                             │  │
│  └──────────────────────┘  └─────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                Builder Layer (构建层)                         │
│  ┌────────────────────────────────────────────────────────┐ │
│  │           ProcessChainBuilder (核心算法)                │ │
│  │  - 双向遍历 (traverseUpward / traverseDownward)        │ │
│  │  - 环检测 (visitedNodesInPath)                         │ │
│  │  - 深度限制 (MAX_TRAVERSE_DEPTH = 50)                  │ │
│  │  - 节点裁剪 (智能评分，保留400个重要节点)                │ │
│  └────────────────────────────────────────────────────────┘ │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                 Util Layer (工具层)                          │
│  ┌──────────────────┐  ┌────────────────┐  ┌─────────────┐ │
│  │AlarmElectionUtil │  │DataConverter   │  │TimeUtil     │ │
│  │- 告警选举算法     │  │- Map→POJO转换  │  │- 时间计算   │ │
│  └──────────────────┘  └────────────────┘  └─────────────┘ │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│           Elasticsearch (RestHighLevelClient)                │
│  - 告警索引 (alarm_index)                                     │
│  - 日志索引 (log_index)                                       │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 快速开始

### 前置要求

- Java 8+
- Maven 3.x
- Elasticsearch 7.x（运行中）

### 1. 配置ES连接

编辑 `src/main/resources/application.yml`:

```yaml
elasticsearch:
  hosts: localhost:9200  # 修改为你的ES地址
  username:              # 如果有认证则填写
  password:              # 如果有认证则填写
```

### 2. 启动应用

**方式1：使用启动脚本（推荐）**

```bash
# Windows
start.bat

# Linux/Mac
./start.sh
```

**方式2：使用Maven**

```bash
mvn spring-boot:run
```

**方式3：打包运行**

```bash
mvn clean package
java -jar target/process-chain-1.0.0.jar
```

### 3. 验证启动

```bash
# 健康检查
curl http://localhost:8080/api/processchain/health

# 响应
{
  "status": "UP",
  "service": "Process Chain Generator"
}
```

## 📡 API 使用

### 单个IP生成进程链

```bash
curl -X GET "http://localhost:8080/api/processchain/generate?ip=192.168.1.100"
```

**参数**：
- `ip` (必填) - 目标IP地址
- `associatedEventId` (可选) - 网端关联事件ID

**响应**：
```json
{
  "incidentId": "incident_123",
  "nodes": [...],
  "edges": [...],
  "foundRootNode": true
}
```

### 批量生成进程链

```bash
curl -X POST "http://localhost:8080/api/processchain/batch-generate" \
  -H "Content-Type: application/json" \
  -d '{
    "ips": ["192.168.1.100", "192.168.1.101"],
    "associatedEventIds": {
      "192.168.1.100": "event_001"
    }
  }'
```

**响应**：
```json
{
  "192.168.1.100": {
    "incidentId": "incident_123",
    "nodes": [...],
    ...
  },
  "192.168.1.101": {
    "incidentId": "incident_124",
    "nodes": [...],
    ...
  }
}
```

## 🎯 核心算法

### 告警选举算法

```
优先级规则：
  1. 网端关联告警 (associatedEventId匹配) - 最高优先级
  2. 高危告警组 (HIGH) - 数量最多优先
  3. 中危告警组 (MEDIUM) - 数量最多优先
  4. 低危告警组 (LOW) - 数量最多优先
```

### 进程链构建算法

```
高危告警：双向遍历
  ├─ 向上追溯父进程 (traverseUpward)
  └─ 向下探查子进程 (traverseDownward)

中低危告警：向上遍历
  └─ 向上追溯父进程 (traverseUpward)

安全保护：
  ├─ 最大深度限制：50层
  ├─ 环检测：visitedNodesInPath
  └─ 节点数限制：400个（超过则智能裁剪）
```

### 智能节点裁剪

当节点数超过400个时，基于重要性评分裁剪：

| 维度 | 分数 |
|------|------|
| 网端关联告警节点 | +1000 |
| 高危告警节点 | +100 |
| 中危告警节点 | +50 |
| 低危告警节点 | +20 |
| 根节点 | +80 |
| 连接数（每个） | +2 (最多+30) |
| 有日志数据 | +10 |
| process类型 | +5 |

## ⚡ 性能优化

### ES批量查询优化

| 场景 | 原方案 | 优化后 | 提升 |
|------|--------|--------|------|
| 10个IP | 20次查询 | 2次查询 | **10倍** |
| 100个IP | 200次查询 | 2次查询 | **100倍** |
| 1000个IP | 2000次查询 | 2次查询 | **1000倍** |

**优化策略**：
- ✅ 使用`MultiSearchRequest`批量查询告警
- ✅ 使用`termsQuery`批量查询日志
- ✅ 日志哈希索引（O(1)查找）
- ✅ 智能节点裁剪（控制内存）

## 📚 文档导航

### 必读文档

| 文档 | 说明 | 重要性 |
|------|------|--------|
| [核心代码详解.md](核心代码详解.md) | 5个核心类的逐行解析 | ⭐⭐⭐⭐⭐ |
| [SpringBoot集成说明.md](SpringBoot集成说明.md) | 项目架构和API文档 | ⭐⭐⭐⭐⭐ |
| [ES性能优化说明.md](ES性能优化说明.md) | ES查询优化策略 | ⭐⭐⭐⭐ |
| [项目文件说明.md](项目文件说明.md) | 完整文件树和阅读指南 | ⭐⭐⭐ |

### 辅助文档

- [ES集成指南.md](ES集成指南.md) - ES集成详细步骤
- [进程链优化说明.md](进程链优化说明.md) - 节点裁剪和安全机制
- [异常处理说明.md](异常处理说明.md) - 异常处理机制
- [快速开始.md](快速开始.md) - 快速上手指南
- [项目改造完成总结.md](项目改造完成总结.md) - 项目完成总结

### 学习路线

**新手入门**：
```
1. 阅读 SpringBoot集成说明.md (了解架构)
2. 阅读 核心代码详解.md (深入算法) ⭐
3. 运行 start.bat (启动项目)
4. 测试 REST API (调用接口)
```

**开发者进阶**：
```
1. 理解 OptimizedESQueryService (批量查询)
2. 掌握 ProcessChainBuilder (构建算法)
3. 调试 traverseUpward/Downward (遍历过程)
4. 扩展 自定义裁剪规则
```

## 🛠️ 项目结构

```
demo/
├── pom.xml                          # Maven配置
├── start.bat                        # 启动脚本
├── build.bat                        # 构建脚本
├── README.md                        # 本文件
├── 核心代码详解.md                    # ⭐ 核心文档
├── [其他文档...]
│
├── src/main/
│   ├── java/com/security/processchain/
│   │   ├── ProcessChainApplication.java           # 启动类
│   │   ├── config/                               # 配置类
│   │   ├── controller/                           # REST API
│   │   ├── model/                                # 数据模型
│   │   ├── service/                              # 服务层
│   │   │   ├── OptimizedESQueryService.java     # ⭐ ES优化
│   │   │   ├── ProcessChainBuilder.java         # ⭐ 构建器
│   │   │   └── impl/ProcessChainServiceImpl.java # ⭐ 服务实现
│   │   └── util/                                 # 工具类
│   │       ├── AlarmElectionUtil.java            # 告警选举
│   │       └── DataConverter.java                # 数据转换
│   └── resources/
│       └── application.yml                        # 配置文件
│
└── src/test/
    └── java/.../SpringBootProcessChainTest.java  # 集成测试
```

## 🔧 配置说明

### application.yml

```yaml
# 服务器配置
server:
  port: 8080

# ES配置
elasticsearch:
  hosts: localhost:9200
  username:                      # 可选
  password:                      # 可选
  connection-timeout: 5000       # 连接超时(ms)
  socket-timeout: 60000          # Socket超时(ms)

# 进程链配置
process-chain:
  alarm-index: alarm_index       # 告警索引
  log-index: log_index           # 日志索引
  max-traversal-depth: 50        # 最大遍历深度
  max-node-count: 400            # 最大节点数
  max-query-size: 10000          # ES查询最大返回数
```

## 🧪 测试

### 运行测试

```bash
mvn test
```

### 测试类

- `SpringBootProcessChainTest` - SpringBoot集成测试
  - `testSingleIpProcessChain()` - 单个IP测试
  - `testBatchProcessChain()` - 批量生成测试
  - `testBatchQueryPerformance()` - 性能对比测试

## 🐛 常见问题

### 1. 连接ES失败

**问题**：`Cannot connect to Elasticsearch`

**解决**：
- 检查ES服务是否运行：`curl http://localhost:9200`
- 确认`application.yml`中的hosts配置正确
- 检查网络和防火墙设置

### 2. 进程链为空

**问题**：返回的进程链没有节点

**排查**：
1. 检查ES中是否有告警数据
2. 检查告警的traceId是否正确
3. 检查日志是否匹配告警
4. 查看控制台警告日志

### 3. 查询超时

**问题**：`SocketTimeoutException`

**解决**：
- 增加`socket-timeout`配置
- 优化ES索引性能
- 减少`max-query-size`

更多问题参考：[核心代码详解.md - 第9章](核心代码详解.md)

## 📊 技术指标

```
核心代码:      ~2,500行
配置文件:      ~100行
文档:         ~6,000行
测试代码:      ~200行
```

**性能指标**：
- 单个IP生成：< 1秒（网络正常）
- 批量10个IP：< 2秒
- 批量100个IP：< 5秒
- 内存占用：< 512MB（400节点）

## 🚀 部署建议

### 开发环境

```bash
# 使用start.bat直接启动
start.bat
```

### 生产环境

```bash
# 1. 打包
mvn clean package -DskipTests

# 2. 运行
java -Xmx2g -Xms1g -jar target/process-chain-1.0.0.jar \
  --spring.config.location=classpath:/application.yml
```

### Docker部署（可选）

```dockerfile
FROM openjdk:8-jre-alpine
COPY target/process-chain-1.0.0.jar /app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## 🤝 贡献指南

欢迎提交Issue和Pull Request！

在提交代码前，请确保：
1. ✅ 代码通过编译
2. ✅ 所有测试通过
3. ✅ 添加了必要的注释
4. ✅ 更新了相关文档

## 📄 许可证

本项目仅供学习和内部使用。

## 📞 技术支持

- 📖 **文档**: 优先阅读[核心代码详解.md](核心代码详解.md)
- 🐛 **问题**: 查看[常见问题](#-常见问题)章节
- 💬 **讨论**: 联系安全开发团队

## 🎯 下一步计划

- [ ] 支持更多日志类型（registry、dll等）
- [ ] 进程链可视化前端
- [ ] 分布式部署支持
- [ ] 性能监控（Prometheus）
- [ ] 缓存优化（Redis）

---

**⭐ 推荐阅读顺序**：
1. 本README（了解项目概况）
2. [SpringBoot集成说明.md](SpringBoot集成说明.md)（了解架构）
3. [核心代码详解.md](核心代码详解.md)（⭐⭐⭐⭐⭐ 深入算法）

项目已Ready for Production！🚀

