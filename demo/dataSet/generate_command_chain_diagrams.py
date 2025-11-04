#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
为命令执行场景的所有案例生成链关系图（只使用第一层级字段）
"""

import json
import os
from collections import defaultdict
from pathlib import Path

def parse_test_data(file_path):
    """解析test_data.txt，只使用第一层级字段"""
    nodes = []
    network_alert = None
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                log_type = data.get('logType', '')
                
                if log_type in ['alert', 'network']:
                    network_alert = data
                else:
                    nodes.append(data)
            except json.JSONDecodeError as e:
                print(f"  跳过无效JSON行: {e}")
    
    return nodes, network_alert

def build_tree(nodes):
    """构建进程树（只使用processGuid和parentProcessGuid）"""
    # 按processGuid索引
    node_map = {node.get('processGuid'): node for node in nodes if node.get('processGuid')}
    
    # 构建父子关系
    children_map = defaultdict(list)
    for node in nodes:
        parent_guid = node.get('parentProcessGuid')
        if parent_guid and parent_guid in node_map:
            children_map[parent_guid].append(node.get('processGuid'))
    
    # 找所有顶层节点（没有父节点或父节点不存在的节点）
    top_level_nodes = []
    for node in nodes:
        parent_guid = node.get('parentProcessGuid')
        if not parent_guid or parent_guid == '' or parent_guid not in node_map:
            top_level_nodes.append(node)
    
    # 如果有多个顶层节点，优先选择：
    # 1. 既有 traceId == processGuid 又有子节点的
    # 2. 有 isRoot 标记的
    # 3. traceId == processGuid 的
    # 4. 有子节点的
    root_node = None
    
    # 策略1: traceId == processGuid 且有子节点
    for node in top_level_nodes:
        guid = node.get('processGuid')
        if guid == node.get('traceId') and guid in children_map:
            root_node = node
            break
    
    # 策略2: 有 isRoot 标记
    if not root_node:
        for node in top_level_nodes:
            if node.get('isRoot'):
                root_node = node
                break
    
    # 策略3: traceId == processGuid
    if not root_node:
        for node in top_level_nodes:
            if node.get('processGuid') == node.get('traceId'):
                root_node = node
                break
    
    # 策略4: 有子节点的第一个
    if not root_node:
        for node in top_level_nodes:
            if node.get('processGuid') in children_map:
                root_node = node
                break
    
    # 最后兜底：第一个顶层节点
    if not root_node and top_level_nodes:
        root_node = top_level_nodes[0]
    
    return root_node, node_map, children_map

def format_node(node):
    """格式化节点显示"""
    process_name = node.get('processName', 'unknown')
    process_guid = node.get('processGuid', '')
    process_id = node.get('processId', 0)
    log_type = node.get('logType', 'process')
    
    if log_type == 'file':
        return f"📄 {process_name} [{process_guid}] (文件日志)"
    elif log_type == 'registry':
        return f"📝 {process_name} [{process_guid}] (注册表日志)"
    else:
        return f"{process_name} [{process_guid}] (PID:{process_id})"

def print_tree(node_guid, node_map, children_map, prefix="", is_last=True, visited=None):
    """递归打印树结构"""
    if visited is None:
        visited = set()
    
    if node_guid in visited:
        return []
    
    visited.add(node_guid)
    
    node = node_map.get(node_guid)
    if not node:
        return []
    
    lines = []
    
    # 当前节点
    connector = "└── " if is_last else "├── "
    lines.append(prefix + connector + format_node(node))
    
    # 子节点
    children = children_map.get(node_guid, [])
    if children:
        extension = "    " if is_last else "│   "
        for i, child_guid in enumerate(children):
            child_is_last = (i == len(children) - 1)
            lines.extend(print_tree(child_guid, node_map, children_map, 
                                   prefix + extension, child_is_last, visited))
    
    return lines

def count_nodes_by_type(nodes):
    """统计各类型节点数量"""
    from collections import Counter
    
    process_names = [n.get('processName') for n in nodes if n.get('logType') == 'process']
    return Counter(process_names)

def get_attack_description(network_alert):
    """从网络告警中获取攻击描述"""
    if not network_alert:
        return "命令执行攻击"
    
    rule_name = network_alert.get('ruleName', network_alert.get('name', ''))
    if '命令执行' in rule_name or 'RCE' in rule_name:
        return rule_name
    return "命令执行攻击"

def generate_chain_diagram(file_path, output_path, case_num):
    """生成链关系图"""
    print(f"  解析数据文件: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"  错误：文件不存在")
        return False
    
    nodes, network_alert = parse_test_data(file_path)
    
    if not nodes:
        print(f"  警告：没有找到节点数据")
        return False
    
    print(f"  总节点数: {len(nodes)}")
    
    root_node, node_map, children_map = build_tree(nodes)
    
    if not root_node:
        print("  错误：找不到根节点！")
        return False
    
    print(f"  根节点: {root_node.get('processName')} [{root_node.get('processGuid')}]")
    
    # 生成树形图
    tree_lines = [format_node(root_node)]
    
    children = children_map.get(root_node.get('processGuid'), [])
    for i, child_guid in enumerate(children):
        is_last = (i == len(children) - 1)
        tree_lines.extend(print_tree(child_guid, node_map, children_map, "", is_last))
    
    # 统计信息
    stats = count_nodes_by_type(nodes)
    
    # 攻击描述
    attack_desc = get_attack_description(network_alert)
    
    # 网络告警信息
    network_info = ""
    if network_alert:
        src = network_alert.get('srcAddress', 'N/A')
        dest = network_alert.get('destAddress', 'N/A')
        network_info = f"- **攻击源**: {src}\n- **攻击目标**: {dest}\n"
    
    # 生成Markdown
    md_lines = [
        f"# 案例{case_num} - 命令执行攻击链关系图",
        "",
        "## 基本信息",
        f"- **主机地址**: {root_node.get('hostAddress', 'N/A')}",
        "- **攻击类型**: 命令执行",
        f"- **攻击描述**: {attack_desc}",
        network_info,
        f"- **根节点**: {root_node.get('processName')} ({root_node.get('logType')}, processGuid: {root_node.get('processGuid')})",
        f"- **总节点数**: {len(nodes)}",
        "",
        "## 完整进程树",
        "",
        "```",
        *tree_lines,
        "```",
        "",
        "## 统计信息",
        "",
        "### 按进程类型统计:",
    ]
    
    for name, count in stats.most_common():
        md_lines.append(f"- **{name}**: {count}个实例")
    
    md_lines.extend([
        "",
        "## 说明",
        "- 所有节点的 `hostAddress` 均为 " + root_node.get('hostAddress', 'N/A'),
        "- 根节点的 `processGuid` 等于 `traceId`",
        "- 所有子节点通过 `parentProcessGuid` 字段连接到父节点的 `processGuid`",
        "- 本图仅使用日志的**第一层级字段**生成，不解析 `otherFields` 等嵌套字段",
    ])
    
    # 写入文件
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(md_lines))
    
    print(f"  链关系图已生成: {output_path}")
    return True

def generate_all_command_chains():
    """为命令执行场景的所有案例生成链关系图"""
    base_dir = Path('demo/dataSet/命令执行')
    
    print("="*60)
    print("开始生成命令执行场景的链关系图")
    print("="*60)
    
    success_count = 0
    
    for case_num in range(2, 6):  # 案例2-5
        case_dir = base_dir / f'案例{case_num}'
        test_data_file = case_dir / 'test_data.txt'
        output_file = case_dir / '链关系图.md'
        
        print(f"\n处理案例{case_num}...")
        
        if test_data_file.exists():
            if generate_chain_diagram(str(test_data_file), str(output_file), case_num):
                success_count += 1
        else:
            print(f"  跳过：test_data.txt不存在")
    
    # 处理案例1（JSON格式，暂时跳过）
    case1_dir = base_dir / '案例1'
    if (case1_dir / 'endpoint1.json').exists():
        print(f"\n处理案例1...")
        print(f"  跳过：案例1为JSON格式，需要特殊处理")
    
    print("\n" + "="*60)
    print(f"完成！成功生成 {success_count} 个链关系图")
    print("="*60)

if __name__ == '__main__':
    generate_all_command_chains()

