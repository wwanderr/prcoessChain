#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""检查数据结构并生成链关系图"""

import json
import os

def analyze_case(test_file):
    """分析案例的数据结构"""
    with open(test_file, 'r', encoding='utf-8') as f:
        data = [json.loads(line) for line in f if line.strip()]
    
    # 分类
    network = None
    files = []
    processes = []
    
    for item in data:
        log_type = item.get('logType', '')
        if log_type == 'alert':
            network = item
        elif log_type == 'file':
            files.append(item)
        elif log_type == 'process':
            processes.append(item)
    
    # 找根节点
    root = None
    for p in processes:
        if p.get('isRoot') or p.get('processGuid') == p.get('traceId'):
            root = p
            break
    
    # 找父节点和祖父节点
    parent = None
    grandparent = None
    
    if root:
        root_guid = root.get('processGuid')
        parent_guid = root.get('parentProcessGuid')
        
        # 找父节点
        for p in processes:
            if p.get('processGuid') == parent_guid:
                parent = p
                break
        
        # 找祖父节点
        if parent:
            grandparent_guid = parent.get('parentProcessGuid')
            for p in processes:
                if p.get('processGuid') == grandparent_guid:
                    grandparent = p
                    break
    
    return {
        'network': network,
        'files': files,
        'processes': processes,
        'root': root,
        'parent': parent,
        'grandparent': grandparent
    }

def main():
    """主函数"""
    scenarios = [
        ('webshell文件上传', 'Webshell文件上传'),
        ('命令执行', '命令执行'),
        ('矿池', '矿池挖矿')
    ]
    
    for folder, name in scenarios:
        print(f'\n{"="*60}')
        print(f'场景: {name}')
        print(f'{"="*60}')
        
        for case_num in range(2, 6):
            test_file = f'{folder}/案例{case_num}/test_data.txt'
            
            if not os.path.exists(test_file):
                print(f'\n案例{case_num}: 文件不存在')
                continue
            
            result = analyze_case(test_file)
            
            print(f'\n案例{case_num}:')
            print(f'  进程数: {len(result["processes"])}')
            print(f'  文件数: {len(result["files"])}')
            print(f'  网络数: {1 if result["network"] else 0}')
            
            if result['root']:
                print(f'  根节点: {result["root"].get("processName")} (PID:{result["root"].get("processId")})')
            else:
                print(f'  根节点: 未找到!')
            
            if result['parent']:
                print(f'  父节点: {result["parent"].get("processName")} (PID:{result["parent"].get("processId")})')
            else:
                print(f'  父节点: 无')
            
            if result['grandparent']:
                print(f'  祖父节点: {result["grandparent"].get("processName")} (PID:{result["grandparent"].get("processId")})')
            else:
                print(f'  祖父节点: 无')
            
            # 检查是否有更高层的祖先
            ancestor_count = 0
            if result['grandparent']:
                great_grandparent_guid = result['grandparent'].get('parentProcessGuid')
                for p in result['processes']:
                    if p.get('processGuid') == great_grandparent_guid:
                        ancestor_count += 1
                        print(f'  [WARNING] 存在曾祖父节点! {p.get("processName")}')
                        break

if __name__ == '__main__':
    main()

