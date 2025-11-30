@echo off
chcp 65001 >nul
echo ========================================
echo 无告警场景快速检查
echo ========================================
echo.

echo 问题：即使去掉alarms为空的判定，还是生成不了进程链
echo.
echo 可能的原因：
echo 1. logs 参数为空
echo 2. eventId 不匹配
echo 3. processGuid 不在图中
echo 4. startLogEventIds 为空
echo.
echo ========================================
echo 请提供以下信息：
echo ========================================
echo.
echo 1. 是否看到日志：【无告警场景】开始处理起点日志?
echo    (是/否): __________
echo.
echo 2. 日志总数是多少？
echo    【无告警场景】日志总数=__________
echo.
echo 3. 匹配的日志数是多少？
echo    【无告警场景】匹配的日志数: _____/_____
echo.
echo 4. 起点节点数是多少？
echo    【起点节点】共 _____ 个起点
echo.
echo 5. 相关节点总数是多少？
echo    【子图提取】相关节点总数=_____
echo.
echo ========================================
echo 调试步骤：
echo ========================================
echo.
echo 步骤1：重新编译
echo   cd demo
echo   mvn clean compile -DskipTests
echo.
echo 步骤2：运行测试并查看日志
echo.
echo 步骤3：复制上述日志内容
echo.
echo 步骤4：根据日志定位问题：
echo   - 如果日志总数=0，说明logs参数为空
echo   - 如果匹配数=0，说明eventId不匹配
echo   - 如果起点数=0，说明processGuid不在图中
echo.
pause

