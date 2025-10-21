@echo off
chcp 65001 >nul
echo ========================================
echo 进程链生成系统 - 启动脚本
echo ========================================
echo.

REM 检查Maven是否安装
where mvn >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未找到Maven，请先安装Maven并配置环境变量
    pause
    exit /b 1
)

echo [1/3] 检查依赖...
call mvn dependency:resolve -q

echo [2/3] 编译项目...
call mvn clean compile -q

if %errorlevel% neq 0 (
    echo [错误] 编译失败，请检查代码
    pause
    exit /b 1
)

echo [3/3] 启动应用...
echo.
echo ========================================
echo 应用启动中，请稍候...
echo 访问地址: http://localhost:8080
echo 健康检查: http://localhost:8080/api/processchain/health
echo ========================================
echo.

call mvn spring-boot:run

pause

