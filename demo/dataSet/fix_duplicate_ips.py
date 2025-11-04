#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复命令执行和矿池场景中与其他场景重复的IP地址
"""

import json
import os
from pathlib import Path
import re

# IP替换映射 - 命令执行场景
COMMAND_EXEC_IP_MAPPING = {
    '10.50.109.192': '10.50.122.205',  # 命令执行场景专用IP
    '10.50.109.152': '10.50.122.206',  # 命令执行场景专用IP
}

# IP替换映射 - 矿池场景  
MINING_IP_MAPPING = {
    '10.50.109.192': '10.50.123.207',  # 矿池场景专用IP
}

def replace_ip_in_json(data, ip_mapping):
    """递归替换JSON中的所有IP地址"""
    if isinstance(data, str):
        result = data
        for old_ip, new_ip in ip_mapping.items():
            result = result.replace(old_ip, new_ip)
        return result
    elif isinstance(data, list):
        return [replace_ip_in_json(item, ip_mapping) for item in data]
    elif isinstance(data, dict):
        return {k: replace_ip_in_json(v, ip_mapping) for k, v in data.items()}
    else:
        return data

def fix_test_data_file(file_path, ip_mapping, scenario_name):
    """修复单个test_data.txt文件中的IP"""
    print(f"  处理文件: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"  跳过: 文件不存在")
        return False
    
    lines = []
    modified_count = 0
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                lines.append('')
                continue
            
            try:
                data = json.loads(line)
                original_json = json.dumps(data, ensure_ascii=False)
                
                # 替换IP
                data = replace_ip_in_json(data, ip_mapping)
                new_json = json.dumps(data, ensure_ascii=False)
                
                if original_json != new_json:
                    modified_count += 1
                    print(f"    第{line_num}行: 已替换IP")
                    for old_ip, new_ip in ip_mapping.items():
                        if old_ip in original_json:
                            print(f"      {old_ip} -> {new_ip}")
                
                lines.append(new_json)
            except json.JSONDecodeError as e:
                print(f"  警告: 第{line_num}行JSON解析失败: {e}")
                lines.append(line)
    
    if modified_count > 0:
        with open(file_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(lines))
        print(f"  已修复 {modified_count} 行数据")
        return True
    else:
        print(f"  无需修复")
        return False

def fix_json_file(file_path, ip_mapping, scenario_name):
    """修复单个JSON文件中的IP"""
    print(f"  处理文件: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"  跳过: 文件不存在")
        return False
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read().strip()
    
    try:
        data = json.loads(content)
        original_json = json.dumps(data, ensure_ascii=False)
        
        # 替换IP
        data = replace_ip_in_json(data, ip_mapping)
        new_json = json.dumps(data, ensure_ascii=False, indent=None)
        
        if original_json != new_json:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_json)
            
            print(f"  已替换IP:")
            for old_ip, new_ip in ip_mapping.items():
                if old_ip in original_json:
                    print(f"    {old_ip} -> {new_ip}")
            return True
        else:
            print(f"  无需修复")
            return False
    except json.JSONDecodeError as e:
        print(f"  错误: JSON解析失败: {e}")
        return False

def fix_scenario(scenario_dir, scenario_name, ip_mapping):
    """修复一个场景下所有案例的IP"""
    print(f"\n{'='*60}")
    print(f"修复场景: {scenario_name}")
    print('='*60)
    
    fixed_count = 0
    
    for case_num in range(1, 6):
        case_dir = scenario_dir / f'案例{case_num}'
        print(f"\n处理案例{case_num}...")
        
        # 修复test_data.txt
        test_data_file = case_dir / 'test_data.txt'
        if test_data_file.exists():
            if fix_test_data_file(str(test_data_file), ip_mapping, scenario_name):
                fixed_count += 1
        
        # 修复JSON文件
        for json_file in case_dir.glob('*.json'):
            if fix_json_file(str(json_file), ip_mapping, scenario_name):
                fixed_count += 1
    
    return fixed_count

def main():
    """主函数"""
    base_dir = Path('demo/dataSet')
    
    print("="*60)
    print("开始修复IP重复问题")
    print("="*60)
    
    total_fixed = 0
    
    # 修复命令执行场景
    command_exec_dir = base_dir / '命令执行'
    if command_exec_dir.exists():
        fixed = fix_scenario(command_exec_dir, '命令执行', COMMAND_EXEC_IP_MAPPING)
        total_fixed += fixed
    
    # 修复矿池场景
    mining_dir = base_dir / '矿池'
    if mining_dir.exists():
        fixed = fix_scenario(mining_dir, '矿池', MINING_IP_MAPPING)
        total_fixed += fixed
    
    print("\n" + "="*60)
    print(f"完成！共修复 {total_fixed} 个文件")
    print("="*60)
    
    print("\n修复后的IP分配：")
    print("- Webshell文件上传: 10.50.109.192, 10.50.110.193, 10.50.111.194, 10.50.112.195, 10.50.113.196")
    print("- 命令执行: 10.50.122.205-206, 10.50.114.197, 10.50.115.198, 10.50.116.199, 10.50.117.200")
    print("- 矿池: 10.50.123.207, 10.50.118.201, 10.50.119.202, 10.50.120.203, 10.50.121.204")

if __name__ == '__main__':
    main()

