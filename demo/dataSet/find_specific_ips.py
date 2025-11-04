#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
查找特定IP在数据中的详细位置
"""

import json
import os
from pathlib import Path

def find_ip_in_dict(data, target_ip, path=""):
    """递归查找IP在字典中的位置"""
    results = []
    
    if isinstance(data, str):
        if target_ip in data:
            results.append(path)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            results.extend(find_ip_in_dict(item, target_ip, f"{path}[{i}]"))
    elif isinstance(data, dict):
        for key, value in data.items():
            results.extend(find_ip_in_dict(value, target_ip, f"{path}.{key}" if path else key))
    
    return results

def check_file(file_path, target_ip):
    """检查单个文件"""
    print(f"\n检查文件: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read().strip()
    
    try:
        data = json.loads(content)
        locations = find_ip_in_dict(data, target_ip)
        
        if locations:
            print(f"  找到 {len(locations)} 处:")
            for loc in locations[:5]:  # 只显示前5个
                print(f"    - {loc}")
                # 显示值
                keys = loc.split('.')
                val = data
                try:
                    for k in keys:
                        if '[' in k:
                            k, idx = k.split('[')
                            idx = int(idx.replace(']', ''))
                            val = val[k][idx] if k else val[idx]
                        else:
                            val = val[k]
                    print(f"      值: {str(val)[:100]}")
                except:
                    pass
        else:
            print(f"  未找到")
    except json.JSONDecodeError as e:
        print(f"  JSON解析失败: {e}")

def main():
    base_dir = Path('demo/dataSet')
    
    # 检查 134.0.0.0
    print("="*60)
    print("查找 134.0.0.0")
    print("="*60)
    
    check_file(base_dir / 'webshell文件上传/案例1/network1.json', '134.0.0.0')
    check_file(base_dir / '命令执行/案例1/network1.json', '134.0.0.0')
    
    # 检查 3.12.15.0
    print("\n" + "="*60)
    print("查找 3.12.15.0")
    print("="*60)
    
    check_file(base_dir / '命令执行/案例1/endpoint1.json', '3.12.15.0')
    check_file(base_dir / '矿池/案例1/endpoint1.json', '3.12.15.0')

if __name__ == '__main__':
    main()

