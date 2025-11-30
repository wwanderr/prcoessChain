@echo off
chcp 65001 >nul
echo ========================================
echo 晚拆分方案测试脚本
echo ========================================
echo.

echo 步骤1：清理并重新编译...
call mvn clean compile -DskipTests
if errorlevel 1 (
    echo.
    echo ❌ 编译失败！
    pause
    exit /b 1
)

echo.
echo ========================================
echo 步骤2：运行晚拆分测试用例...
echo ========================================
echo.

call mvn test -Dtest=LateEntityExtractionTest
if errorlevel 1 (
    echo.
    echo ❌ 测试失败！请查看上面的日志
    pause
    exit /b 1
)

echo.
echo ========================================
echo ✅ 测试完成！
echo ========================================
echo.
echo 请检查上面的日志，确认:
echo 1. 【建图后】节点都是 nodeType=process
echo 2. 【实体提取】创建实体节点数 ^> 0
echo 3. 【实体提取后】有 file_entity 和 domain_entity 节点
echo.
pause

