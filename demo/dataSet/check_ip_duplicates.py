#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检查所有场景中IP地址的使用情况，找出重复的IP
"""

import json
import os
from pathlib import Path
from collections import defaultdict

def extract_ips_from_value(value, ips, excluded_keys=None):
    """递归提取值中的IP地址"""
    import re
    
    if excluded_keys is None:
        excluded_keys = set()
    
    if isinstance(value, str):
        # 匹配IP地址模式
        ip_pattern = r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|(?:\d{1,3}\.){3}\d{1,3})\b'
        found_ips = re.findall(ip_pattern, value)
        for ip in found_ips:
            # 排除设备地址段 10.50.86.x 和基础设施IP
            if not ip.startswith('10.50.86.') and ip != '78.118.0.12':
                ips.add(ip)
    elif isinstance(value, list):
        for item in value:
            extract_ips_from_value(item, ips, excluded_keys)
    elif isinstance(value, dict):
        for k, v in value.items():
            # 排除版本号字段
            if k not in ['deviceVersion', 'appVersion']:
                extract_ips_from_value(v, ips, excluded_keys)

def extract_ips_from_line(line):
    """从JSON行中提取所有IP地址"""
    ips = set()
    try:
        data = json.loads(line)
        
        # 递归遍历所有字段提取IP
        extract_ips_from_value(data, ips)
        
        return ips
    except:
        return set()

def scan_scenario(scenario_dir, scenario_name):
    """扫描一个场景目录下所有案例的IP"""
    scenario_ips = defaultdict(list)  # IP -> [(案例号, 文件)]
    
    for case_num in range(1, 6):
        case_dir = scenario_dir / f'案例{case_num}'
        
        # 检查test_data.txt
        test_data_file = case_dir / 'test_data.txt'
        if test_data_file.exists():
            with open(test_data_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    ips = extract_ips_from_line(line.strip())
                    for ip in ips:
                        scenario_ips[ip].append((case_num, 'test_data.txt', line_num))
        
        # 检查JSON文件
        for json_file in case_dir.glob('*.json'):
            with open(json_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                ips = extract_ips_from_line(content)
                for ip in ips:
                    scenario_ips[ip].append((case_num, json_file.name, 1))
    
    return scenario_ips

def check_all_scenarios():
    """检查所有场景的IP使用情况"""
    base_dir = Path('demo/dataSet')
    
    scenarios = {
        'webshell文件上传': base_dir / 'webshell文件上传',
        '命令执行': base_dir / '命令执行',
        '矿池': base_dir / '矿池'
    }
    
    all_ips = {}  # IP -> [(场景, 案例号, 文件)]
    
    print("="*70)
    print("扫描所有场景的IP地址使用情况")
    print("="*70)
    
    for scenario_name, scenario_dir in scenarios.items():
        if not scenario_dir.exists():
            continue
        
        print(f"\n扫描场景: {scenario_name}")
        scenario_ips = scan_scenario(scenario_dir, scenario_name)
        
        # 记录到总表
        for ip, locations in scenario_ips.items():
            if ip not in all_ips:
                all_ips[ip] = []
            for case_num, filename, line_num in locations:
                all_ips[ip].append((scenario_name, case_num, filename, line_num))
        
        print(f"  发现 {len(scenario_ips)} 个不同的IP地址")
    
    # 检查跨场景重复
    print("\n" + "="*70)
    print("检查跨场景IP重复情况")
    print("="*70)
    
    duplicates = {}
    for ip, locations in all_ips.items():
        scenarios_using = set(loc[0] for loc in locations)
        if len(scenarios_using) > 1:
            duplicates[ip] = locations
    
    if duplicates:
        print(f"\n发现 {len(duplicates)} 个IP地址在多个场景中重复使用：\n")
        
        for ip in sorted(duplicates.keys()):
            locations = duplicates[ip]
            print(f"IP: {ip}")
            by_scenario = defaultdict(list)
            for scenario, case_num, filename, line_num in locations:
                by_scenario[scenario].append((case_num, filename, line_num))
            
            for scenario in sorted(by_scenario.keys()):
                cases = by_scenario[scenario]
                case_list = ', '.join([f"案例{c[0]}" for c in cases])
                print(f"  - {scenario}: {case_list}")
            print()
    else:
        print("\n✓ 没有发现跨场景的IP重复使用")
    
    # 检查每个场景内部的IP使用
    print("\n" + "="*70)
    print("各场景IP分配情况")
    print("="*70)
    
    for scenario_name, scenario_dir in scenarios.items():
        if not scenario_dir.exists():
            continue
        
        scenario_ips = scan_scenario(scenario_dir, scenario_name)
        
        print(f"\n{scenario_name}:")
        case_ips = defaultdict(set)
        
        for ip, locations in scenario_ips.items():
            for case_num, filename, line_num in locations:
                case_ips[case_num].add(ip)
        
        for case_num in sorted(case_ips.keys()):
            ips = sorted(case_ips[case_num])
            print(f"  案例{case_num}: {', '.join(ips)}")
    
    return duplicates

if __name__ == '__main__':
    duplicates = check_all_scenarios()

