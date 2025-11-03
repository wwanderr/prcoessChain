#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
修复测试用例的traceId结构
规则：
1. 根节点（告警进程）: processGuid == traceId
2. 根节点向上最多2层，这2层保持相同的traceId
3. 2层以上的进程使用不同的traceId
"""
import json
import os

def fix_trace_structure(file_path):
    """修复单个文件的traceId结构"""
    print(f'\n处理文件: {file_path}')
    
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # 第一步：解析所有进程
    processes = []
    alert_line = None
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        try:
            data = json.loads(line)
            log_type = data.get('logType', '')
            
            if log_type == 'alert':
                alert_line = data
            elif log_type in ['process', 'file']:
                processes.append(data)
        except:
            pass
    
    if not processes:
        print('  [SKIP] 没有进程数据')
        return
    
    # 第二步：构建进程关系映射
    guid_to_process = {}
    for proc in processes:
        guid = proc.get('processGuid')
        if guid:
            guid_to_process[guid] = proc
    
    # 第三步：找到根节点（最后一个进程通常是告警进程，或者有病毒文件的进程）
    root_process = None
    for proc in processes:
        if proc.get('logType') == 'file' and proc.get('virusName'):
            # 文件节点，找它对应的进程
            root_guid = proc.get('processGuid')
            if root_guid in guid_to_process:
                root_process = guid_to_process[root_guid]
                break
    
    if not root_process:
        # 没有病毒文件，找最可疑的进程（php-cgi, cmd, MsCpuCN64等）
        for proc in processes:
            if proc.get('logType') == 'process':
                name = proc.get('processName', '').lower()
                if any(s in name for s in ['php-cgi', 'cmd', 'mscpucn64', 'whoami']):
                    root_process = proc
                    break
    
    if not root_process:
        root_process = processes[0]  # 使用第一个进程
    
    root_guid = root_process.get('processGuid')
    original_trace_id = root_process.get('traceId')
    
    print(f'  根节点: {root_process.get("processName")} (GUID: {root_guid})')
    print(f'  原始TraceId: {original_trace_id}')
    
    # 第四步：向上追溯，标记层级
    levels = {}  # guid -> level (0=root, 1=parent, 2=grandparent, 3+=other)
    
    def assign_levels(guid, level=0):
        if guid in levels:
            return
        if guid not in guid_to_process:
            return
        
        levels[guid] = level
        proc = guid_to_process[guid]
        parent_guid = proc.get('parentProcessGuid')
        
        if parent_guid and parent_guid in guid_to_process:
            assign_levels(parent_guid, level + 1)
    
    assign_levels(root_guid, 0)
    
    # 第五步：向下遍历所有子节点，标记为level 0（属于根节点的traceId）
    def assign_children_level(guid):
        if guid not in guid_to_process:
            return
        
        # 找所有以此guid为父的子节点
        for proc in processes:
            if proc.get('parentProcessGuid') == guid:
                child_guid = proc.get('processGuid')
                if child_guid and child_guid not in levels:
                    levels[child_guid] = 0
                    assign_children_level(child_guid)
    
    assign_children_level(root_guid)
    
    # 第六步：修改数据
    modified_count = 0
    
    # 修改根节点：processGuid = traceId
    root_process['processGuid'] = original_trace_id
    root_process['traceId'] = original_trace_id
    
    # 更新guid_to_process映射
    if root_guid != original_trace_id:
        guid_to_process[original_trace_id] = root_process
        if root_guid in guid_to_process:
            del guid_to_process[root_guid]
        
        # 更新所有子进程的parentProcessGuid
        for proc in processes:
            if proc.get('parentProcessGuid') == root_guid:
                proc['parentProcessGuid'] = original_trace_id
    
    modified_count += 1
    
    # 修改其他进程的traceId
    for proc in processes:
        guid = proc.get('processGuid')
        if not guid:
            continue
        
        level = levels.get(guid, 0)
        
        if level <= 2:
            # 0-2层：使用根节点的traceId
            if proc.get('traceId') != original_trace_id:
                proc['traceId'] = original_trace_id
                modified_count += 1
        else:
            # 3层及以上：使用不同的traceId
            new_trace_id = f"{original_trace_id.split('-')[0]}-parent-{guid[:8]}"
            if proc.get('traceId') != new_trace_id:
                proc['traceId'] = new_trace_id
                modified_count += 1
    
    # 第七步：写回文件
    new_lines = []
    
    # 先写告警
    if alert_line:
        new_lines.append(json.dumps(alert_line, ensure_ascii=False) + '\n')
    
    # 再写进程（按照原始顺序）
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        try:
            data = json.loads(line)
            if data.get('logType') in ['process', 'file']:
                # 找到对应的修改后的数据
                guid = data.get('processGuid')
                for proc in processes:
                    if proc.get('processGuid') == guid or (guid == root_guid and proc.get('processGuid') == original_trace_id):
                        new_lines.append(json.dumps(proc, ensure_ascii=False) + '\n')
                        break
        except:
            pass
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    
    print(f'  [OK] 修改了 {modified_count} 条记录')
    
    # 打印层级信息
    print(f'  层级分布:')
    level_counts = {}
    for guid, level in levels.items():
        level_counts[level] = level_counts.get(level, 0) + 1
        if level <= 3:
            proc = guid_to_process.get(guid) or guid_to_process.get(original_trace_id)
            if proc:
                trace_id = proc.get('traceId', 'N/A')
                print(f'    Level {level}: {proc.get("processName", "N/A"):20} (TraceId: {trace_id})')

# 配置
test_files = [
    'webshell文件上传/案例2/test_data.txt',
    'webshell文件上传/案例3/test_data.txt',
    'webshell文件上传/案例4/test_data.txt',
    'webshell文件上传/案例5/test_data.txt',
    '命令执行/案例2/test_data.txt',
    '命令执行/案例3/test_data.txt',
    '命令执行/案例4/test_data.txt',
    '命令执行/案例5/test_data.txt',
    '矿池/案例2/test_data.txt',
    '矿池/案例3/test_data.txt',
    '矿池/案例4/test_data.txt',
    '矿池/案例5/test_data.txt',
]

print('='*80)
print('开始修复测试用例的traceId结构')
print('='*80)

for file_path in test_files:
    if os.path.exists(file_path):
        fix_trace_structure(file_path)
    else:
        print(f'\n[SKIP] 文件不存在: {file_path}')

print('\n' + '='*80)
print('所有测试用例修复完成！')
print('='*80)



