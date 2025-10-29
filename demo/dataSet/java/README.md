# 时间戳更新工具

## 功能说明
这个Java程序用于批量更新 `demo/dataSet` 目录下所有JSON文件中的时间字段为当前时间。

## 目标目录
程序会处理以下目录中的所有JSON文件：
- `demo/dataSet/webshell文件上传`
- `demo/dataSet/命令执行`
- `demo/dataSet/矿池`

## 支持的时间字段
- `startTime` - 标准时间格式 (yyyy-MM-dd HH:mm:ss)
- `endTime` - 标准时间格式
- `collectorReceiptTime` - 标准时间格式
- `deviceReceiptTime` - 标准时间格式
- `@timestamp` - ISO格式 (yyyy-MM-dd'T'HH:mm:ss.SSS'Z')
- `baas_sink_process_time` - 时间戳（数字）
- `eventTime` - 时间戳（数字）
- `createdTime` - 时间戳（字符串）
- `processCreateTime` - 时间戳（字符串）

## 使用方法

### 在IDEA中运行
1. 打开 `UpdateTimestamps.java` 文件
2. 右键点击文件，选择 "Run 'UpdateTimestamps.main()'"
3. 或者点击文件右上角的绿色运行按钮

### 命令行运行
```bash
cd demo/dataSet/java
javac UpdateTimestamps.java
java UpdateTimestamps
```

## 输出示例
```
============================================================
时间戳更新工具
============================================================
当前时间: 2025-01-27 15:30:45
当前时间戳: 1737975045000
目标目录: demo/dataSet
------------------------------------------------------------
处理目录: demo/dataSet/webshell文件上传
  处理文件: 案例1/endpoint1.json
    ✓ 已更新
  处理文件: 案例1/network1.json
    - 无需更新
------------------------------------------------------------
更新完成: 共处理 15 个文件，更新 12 个文件
============================================================
```

## 注意事项
- 程序会自动递归处理所有子目录
- 只处理 `.json` 文件
- 保持原有文件格式和编码
- 如果文件不包含时间字段，会显示"无需更新"
