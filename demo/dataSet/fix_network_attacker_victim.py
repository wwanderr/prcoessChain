#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复所有案例中网侧数据的attacker和victim字段，使其与srcAddress和destAddress一致
"""

import json
import os
from pathlib import Path

def fix_network_log(log_data):
    """修复单条网络日志的attacker和victim字段"""
    if log_data.get('logType') not in ['alert', 'network']:
        return log_data, False
    
    src_address = log_data.get('srcAddress', '')
    dest_address = log_data.get('destAddress', '')
    
    modified = False
    
    # 修复attacker字段
    if 'attacker' in log_data:
        old_attacker = log_data['attacker']
        new_attacker = [src_address] if src_address else []
        if old_attacker != new_attacker:
            log_data['attacker'] = new_attacker
            modified = True
            print(f"  修复attacker: {old_attacker} -> {new_attacker}")
    
    # 修复victim字段
    if 'victim' in log_data:
        old_victim = log_data['victim']
        new_victim = [dest_address] if dest_address else []
        if old_victim != new_victim:
            log_data['victim'] = new_victim
            modified = True
            print(f"  修复victim: {old_victim} -> {new_victim}")
    
    return log_data, modified

def fix_test_data_file(file_path):
    """修复单个test_data.txt文件"""
    print(f"\n处理文件: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"  跳过: 文件不存在")
        return
    
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
                data, is_modified = fix_network_log(data)
                if is_modified:
                    modified_count += 1
                    print(f"    第{line_num}行已修复")
                lines.append(json.dumps(data, ensure_ascii=False))
            except json.JSONDecodeError as e:
                print(f"  警告: 第{line_num}行JSON解析失败: {e}")
                lines.append(line)
    
    if modified_count > 0:
        with open(file_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(lines))
        print(f"  已修复 {modified_count} 条网络日志")
    else:
        print(f"  无需修复")

def fix_all_cases():
    """修复所有三种场景的所有案例"""
    base_dir = Path('demo/dataSet')
    
    scenarios = [
        'webshell文件上传',
        '命令执行',
        '矿池'
    ]
    
    total_fixed = 0
    
    for scenario in scenarios:
        print(f"\n{'='*60}")
        print(f"场景: {scenario}")
        print('='*60)
        
        scenario_dir = base_dir / scenario
        if not scenario_dir.exists():
            print(f"跳过: 目录不存在")
            continue
        
        # 遍历案例1-5
        for case_num in range(1, 6):
            case_dir = scenario_dir / f'案例{case_num}'
            test_data_file = case_dir / 'test_data.txt'
            
            if test_data_file.exists():
                fix_test_data_file(str(test_data_file))
                total_fixed += 1
    
    print(f"\n{'='*60}")
    print(f"总计处理了 {total_fixed} 个案例")
    print('='*60)

if __name__ == '__main__':
    fix_all_cases()

