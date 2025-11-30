@echo off
REM 晚拆分方案验证脚本 (Windows版本)

echo =========================================
echo 晚拆分方案验证脚本
echo =========================================
echo.

REM 1. 检查关键文件是否存在
echo 步骤1：检查关键文件...
echo.

set "all_exist=true"

if exist "src\main\java\com\security\processchain\util\EntityExtractor.java" (
    echo OK EntityExtractor.java
) else (
    echo X EntityExtractor.java 不存在
    set "all_exist=false"
)

if exist "src\main\java\com\security\processchain\service\Pro`cessChainGraphBuilder.java" (
    echo OK ProcessChainGraphBuilder.java
) else (
    echo X ProcessChainGraphBuilder.java 不存在
    set "all_exist=false"
)

if exist "src\main\java\com\security\processchain\service\ProcessChainBuilder.java" (
    echo OK ProcessChainBuilder.java
) else (
    echo X ProcessChainBuilder.java 不存在
    set "all_exist=false"
)

if "%all_exist%"=="false" (
    echo.
    echo X 关键文件缺失，请检查代码是否正确部署
    exit /b 1
)

echo.
echo 步骤2：检查EntityExtractor是否包含正确的方法...
echo.

findstr /C:"extractEntitiesFromGraph" "src\main\java\com\security\processchain\util\EntityExtractor.java" >nul
if %errorlevel%==0 (
    echo OK EntityExtractor.extractEntitiesFromGraph方法存在
) else (
    echo X EntityExtractor.extractEntitiesFromGraph方法不存在
    exit /b 1
)

echo.
echo 步骤3：检查ProcessChainBuilder是否调用了EntityExtractor...
echo.

findstr /C:"EntityExtractor.extractEntitiesFromGraph" "src\main\java\com\security\processchain\service\ProcessChainBuilder.java" >nul
if %errorlevel%==0 (
    echo OK ProcessChainBuilder调用了EntityExtractor.extractEntitiesFromGraph
) else (
    echo X ProcessChainBuilder没有调用EntityExtractor.extractEntitiesFromGraph
    exit /b 1
)

echo.
echo 步骤4：检查ProcessChainGraphBuilder是否移除了LogNodeSplitter调用...
echo.

findstr /C:"LogNodeSplitter.splitLogNode" "src\main\java\com\security\processchain\service\ProcessChainGraphBuilder.java" >nul
if %errorlevel%==0 (
    echo 警告 ProcessChainGraphBuilder仍在使用LogNodeSplitter
    echo     这是错误的！应该移除LogNodeSplitter的调用
    exit /b 1
) else (
    echo OK ProcessChainGraphBuilder已移除LogNodeSplitter调用
)

echo.
echo 步骤5：检查是否已编译...
echo.

if exist "target\classes\com\security\processchain\util\EntityExtractor.class" (
    echo OK EntityExtractor.class已生成
) else (
    echo X EntityExtractor.class未生成，需要重新编译
    echo.
    echo 请运行: mvn clean compile -DskipTests
    exit /b 1
)

echo.
echo =========================================
echo OK 所有检查通过！
echo =========================================
echo.
echo 下一步：
echo 1. 运行测试
echo 2. 查看日志，搜索关键词: 【实体提取】
echo 3. 确认日志中有: '创建实体节点=XX' (XX ^> 0)
echo.

