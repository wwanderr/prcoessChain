@echo off
chcp 65001 >nul
echo ========================================
echo 进程链生成系统 - 构建脚本
echo ========================================
echo.

REM 检查Maven是否安装
where mvn >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未找到Maven，请先安装Maven并配置环境变量
    pause
    exit /b 1
)

echo [1/3] 清理旧构建...
call mvn clean -q

echo [2/3] 编译代码...
call mvn compile -q

if %errorlevel% neq 0 (
    echo [错误] 编译失败，请检查代码
    pause
    exit /b 1
)

echo [3/3] 打包应用...
call mvn package -DskipTests -q

if %errorlevel% neq 0 (
    echo [错误] 打包失败
    pause
    exit /b 1
)

echo.
echo ========================================
echo 构建成功！
echo JAR文件位置: target\process-chain-1.0.0.jar
echo.
echo 运行命令:
echo   java -jar target\process-chain-1.0.0.jar
echo ========================================
echo.

pause

