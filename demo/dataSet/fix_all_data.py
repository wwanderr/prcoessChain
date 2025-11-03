#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""修复所有test_data.txt,确保根节点向上最多2层"""

import json
import os

def fix_case(test_file):
    """修复单个案例的数据"""
    print(f'\n处理: {test_file}')
    
    with open(test_file, 'r', encoding='utf-8') as f:
        data = [json.loads(line) for line in f if line.strip()]
    
    # 分类
    processes = []
    non_processes = []
    
    for item in data:
        if item.get('logType') == 'process':
            processes.append(item)
        else:
            non_processes.append(item)
    
    if not processes:
        print('  没有进程节点,跳过')
        return False
    
    # 找根节点
    root = None
    for p in processes:
        if p.get('isRoot') or p.get('processGuid') == p.get('traceId'):
            root = p
            break
    
    # 如果没有明确的根节点,选择第一个进程作为根节点
    if not root:
        # 尝试找告警进程或severity最高的进程
        root = max(processes, key=lambda p: p.get('severity', 0))
        root['isRoot'] = True
        root['isAlarm'] = True
        # 设置traceId = processGuid
        root['traceId'] = root.get('processGuid', f"traceId-{root.get('processId', 999)}")
        print(f'  设置根节点: {root.get("processName")} (PID:{root.get("processId")})')
    
    root_guid = root.get('processGuid')
    root_trace_id = root.get('traceId')
    
    # 建立进程映射
    guid_map = {}
    for p in processes:
        guid = p.get('processGuid')
        if guid:
            guid_map[guid] = p
    
    # 找父节点和祖父节点
    parent_guid = root.get('parentProcessGuid')
    parent = guid_map.get(parent_guid) if parent_guid else None
    
    grandparent_guid = parent.get('parentProcessGuid') if parent else None
    grandparent = guid_map.get(grandparent_guid) if grandparent_guid else None
    
    # 找根节点的所有后代(使用BFS避免循环)
    def get_descendants(node_guid):
        """使用BFS获取所有后代,避免循环引用"""
        descendants = []
        visited = set()
        queue = [node_guid]
        
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            
            for p in processes:
                p_guid = p.get('processGuid')
                parent_guid = p.get('parentProcessGuid')
                if parent_guid == current and p_guid not in visited:
                    descendants.append(p)
                    queue.append(p_guid)
        
        return descendants
    
    root_descendants = get_descendants(root_guid)
    
    # 修复traceId
    # 1. 根节点: traceId = processGuid (已设置)
    # 2. 父节点和祖父节点: 使用不同的traceId
    # 3. 根节点的所有后代: 使用根节点的traceId
    
    modified_count = 0
    
    # 设置父节点的traceId
    if parent:
        old_trace = parent.get('traceId')
        new_trace = f"traceId-parent-{parent.get('processGuid', 'unknown')[-8:]}"
        if old_trace != new_trace:
            parent['traceId'] = new_trace
            modified_count += 1
            print(f'  修改父节点 {parent.get("processName")} traceId: {old_trace} -> {new_trace}')
    
    # 设置祖父节点的traceId
    if grandparent:
        old_trace = grandparent.get('traceId')
        new_trace = f"traceId-grandpa-{grandparent.get('processGuid', 'unknown')[-8:]}"
        if old_trace != new_trace:
            grandparent['traceId'] = new_trace
            modified_count += 1
            print(f'  修改祖父节点 {grandparent.get("processName")} traceId: {old_trace} -> {new_trace}')
    
    # 设置后代节点的traceId
    for desc in root_descendants:
        old_trace = desc.get('traceId')
        if old_trace != root_trace_id:
            desc['traceId'] = root_trace_id
            modified_count += 1
            print(f'  修改后代节点 {desc.get("processName")} traceId: {old_trace} -> {root_trace_id}')
    
    # 删除曾祖父及以上的节点
    valid_guids = {root_guid}
    if parent:
        valid_guids.add(parent.get('processGuid'))
    if grandparent:
        valid_guids.add(grandparent.get('processGuid'))
    for desc in root_descendants:
        valid_guids.add(desc.get('processGuid'))
    
    # 过滤掉多余的祖先节点
    original_process_count = len(processes)
    processes = [p for p in processes if p.get('processGuid') in valid_guids]
    removed_count = original_process_count - len(processes)
    
    if removed_count > 0:
        print(f'  删除了 {removed_count} 个多余的祖先节点')
    
    # 修复non-process节点的traceId
    for item in non_processes:
        if item.get('traceId') and item.get('traceId') != root_trace_id:
            item['traceId'] = root_trace_id
            modified_count += 1
    
    # 写回文件
    if modified_count > 0 or removed_count > 0:
        # 按类型排序: network -> file -> process (按PID排序)
        network = [item for item in non_processes if item.get('logType') == 'alert']
        files = [item for item in non_processes if item.get('logType') == 'file']
        registries = [item for item in non_processes if item.get('logType') == 'registry']
        
        processes.sort(key=lambda p: p.get('processId', 0))
        
        all_data = network + files + registries + processes
        
        with open(test_file, 'w', encoding='utf-8') as f:
            for item in all_data:
                f.write(json.dumps(item, ensure_ascii=False) + '\n')
        
        print(f'  [OK] 已修改 {modified_count} 个字段, 删除 {removed_count} 个节点')
        return True
    else:
        print(f'  无需修改')
        return False

def main():
    """主函数"""
    scenarios = [
        ('webshell文件上传', 'Webshell文件上传'),
        ('命令执行', '命令执行'),
        ('矿池', '矿池挖矿')
    ]
    
    total_fixed = 0
    
    for folder, name in scenarios:
        print(f'\n{"="*60}')
        print(f'场景: {name}')
        print(f'{"="*60}')
        
        for case_num in range(2, 6):
            test_file = f'{folder}/案例{case_num}/test_data.txt'
            
            if not os.path.exists(test_file):
                print(f'\n案例{case_num}: 文件不存在')
                continue
            
            if fix_case(test_file):
                total_fixed += 1
    
    print(f'\n{"="*60}')
    print(f'完成! 共修复 {total_fixed} 个案例')
    print(f'{"="*60}')

if __name__ == '__main__':
    main()

