#!/bin/bash
# 晚拆分方案验证脚本

echo "========================================="
echo "晚拆分方案验证脚本"
echo "========================================="
echo ""

# 1. 检查关键文件是否存在
echo "步骤1：检查关键文件..."
echo ""

files=(
    "src/main/java/com/security/processchain/util/EntityExtractor.java"
    "src/main/java/com/security/processchain/service/ProcessChainGraphBuilder.java"
    "src/main/java/com/security/processchain/service/ProcessChainBuilder.java"
)

all_exist=true
for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file 不存在"
        all_exist=false
    fi
done

if [ "$all_exist" = false ]; then
    echo ""
    echo "❌ 关键文件缺失，请检查代码是否正确部署"
    exit 1
fi

echo ""
echo "步骤2：检查EntityExtractor是否包含正确的方法..."
echo ""

if grep -q "extractEntitiesFromGraph" "src/main/java/com/security/processchain/util/EntityExtractor.java"; then
    echo "✅ EntityExtractor.extractEntitiesFromGraph() 方法存在"
else
    echo "❌ EntityExtractor.extractEntitiesFromGraph() 方法不存在"
    exit 1
fi

echo ""
echo "步骤3：检查ProcessChainBuilder是否调用了EntityExtractor..."
echo ""

if grep -q "EntityExtractor.extractEntitiesFromGraph" "src/main/java/com/security/processchain/service/ProcessChainBuilder.java"; then
    echo "✅ ProcessChainBuilder 调用了 EntityExtractor.extractEntitiesFromGraph()"
else
    echo "❌ ProcessChainBuilder 没有调用 EntityExtractor.extractEntitiesFromGraph()"
    exit 1
fi

echo ""
echo "步骤4：检查ProcessChainGraphBuilder是否移除了LogNodeSplitter调用..."
echo ""

if grep -q "LogNodeSplitter.splitLogNode" "src/main/java/com/security/processchain/service/ProcessChainGraphBuilder.java"; then
    echo "⚠️  ProcessChainGraphBuilder 仍在使用 LogNodeSplitter（早拆分）"
    echo "    这是错误的！应该移除 LogNodeSplitter 的调用"
    exit 1
else
    echo "✅ ProcessChainGraphBuilder 已移除 LogNodeSplitter 调用（晚拆分）"
fi

echo ""
echo "步骤5：检查是否已编译..."
echo ""

if [ -f "target/classes/com/security/processchain/util/EntityExtractor.class" ]; then
    echo "✅ EntityExtractor.class 已生成"
else
    echo "❌ EntityExtractor.class 未生成，需要重新编译"
    echo ""
    echo "请运行: mvn clean compile -DskipTests"
    exit 1
fi

echo ""
echo "========================================="
echo "✅ 所有检查通过！"
echo "========================================="
echo ""
echo "下一步："
echo "1. 运行测试: mvn test -Dtest=ProcessChainIntegrationTest"
echo "2. 查看日志，搜索关键词: 【实体提取】"
echo "3. 确认日志中有: '创建实体节点=XX' (XX > 0)"
echo ""

