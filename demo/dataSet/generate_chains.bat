@echo off
chcp 65001 > nul
cd java

set "CP=.;..\..\..\target\classes;C:\Users\18395\.m2\repository\com\fasterxml\jackson\core\jackson-core\2.13.5\jackson-core-2.13.5.jar;C:\Users\18395\.m2\repository\com\fasterxml\jackson\core\jackson-databind\2.13.5\jackson-databind-2.13.5.jar;C:\Users\18395\.m2\repository\com\fasterxml\jackson\core\jackson-annotations\2.13.5\jackson-annotations-2.13.5.jar"

echo Generating chain diagrams for all test cases...
echo.

REM webshell
echo [webshell] Case 2...
java -cp "%CP%" ChainVisualizer "..\webshell文件上传\案例2\test_data.txt"

echo [webshell] Case 3...
java -cp "%CP%" ChainVisualizer "..\webshell文件上传\案例3\test_data.txt"

echo [webshell] Case 4...
java -cp "%CP%" ChainVisualizer "..\webshell文件上传\案例4\test_data.txt"

echo [webshell] Case 5...
java -cp "%CP%" ChainVisualizer "..\webshell文件上传\案例5\test_data.txt"

REM command
echo [command] Case 2...
java -cp "%CP%" ChainVisualizer "..\命令执行\案例2\test_data.txt"

echo [command] Case 3...
java -cp "%CP%" ChainVisualizer "..\命令执行\案例3\test_data.txt"

echo [command] Case 4...
java -cp "%CP%" ChainVisualizer "..\命令执行\案例4\test_data.txt"

echo [command] Case 5...
java -cp "%CP%" ChainVisualizer "..\命令执行\案例5\test_data.txt"

REM mining
echo [mining] Case 2...
java -cp "%CP%" ChainVisualizer "..\矿池\案例2\test_data.txt"

echo [mining] Case 3...
java -cp "%CP%" ChainVisualizer "..\矿池\案例3\test_data.txt"

echo [mining] Case 4...
java -cp "%CP%" ChainVisualizer "..\矿池\案例4\test_data.txt"

echo [mining] Case 5...
java -cp "%CP%" ChainVisualizer "..\矿池\案例5\test_data.txt"

echo.
echo Done!
cd ..


