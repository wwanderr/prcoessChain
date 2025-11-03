#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import sys

# 设置Java classpath
JAVA_HOME = r"C:\Users\18395\.m2\repository\com\fasterxml\jackson"
CLASSPATH = (
    f"java;"
    f"..\\target\\classes;"
    f"{JAVA_HOME}\\core\\jackson-core\\2.13.5\\jackson-core-2.13.5.jar;"
    f"{JAVA_HOME}\\core\\jackson-databind\\2.13.5\\jackson-databind-2.13.5.jar;"
    f"{JAVA_HOME}\\core\\jackson-annotations\\2.13.5\\jackson-annotations-2.13.5.jar"
)

# 所有要处理的测试案例
test_cases = [
    ("webshell文件上传", "案例2"),
    ("webshell文件上传", "案例3"),
    ("webshell文件上传", "案例4"),
    ("webshell文件上传", "案例5"),
    ("命令执行", "案例2"),
    ("命令执行", "案例3"),
    ("命令执行", "案例4"),
    ("命令执行", "案例5"),
    ("矿池", "案例2"),
    ("矿池", "案例3"),
    ("矿池", "案例4"),
    ("矿池", "案例5"),
]

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    java_dir = os.path.join(base_dir, "java")
    
    success_count = 0
    fail_count = 0
    
    for scenario, case in test_cases:
        test_file = os.path.join(base_dir, scenario, case, "test_data.txt")
        
        if not os.path.exists(test_file):
            print(f"× 跳过 {scenario}/{case} - 文件不存在")
            fail_count += 1
            continue
        
        print(f"正在生成 {scenario}/{case} 的链关系图...", end=" ")
        
        try:
            # 运行Java程序
            result = subprocess.run(
                ["java", "-cp", CLASSPATH, "ChainVisualizer", test_file],
                cwd=java_dir,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0:
                print("✓")
                success_count += 1
            else:
                print(f"× 失败")
                if result.stderr:
                    print(f"  错误: {result.stderr[:200]}")
                fail_count += 1
        except Exception as e:
            print(f"× 异常: {str(e)[:100]}")
            fail_count += 1
    
    print("\n" + "="*60)
    print(f"完成! 成功: {success_count}, 失败: {fail_count}")
    print("="*60)

if __name__ == "__main__":
    main()


