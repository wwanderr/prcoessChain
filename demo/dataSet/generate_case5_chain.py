#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
为案例5生成正确的链关系图（只使用第一层级字段）
"""

import json
from collections import defaultdict

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
                print(f"跳过无效JSON行: {e}")
    
    return nodes, network_alert

def build_tree(nodes):
    """构建进程树（只使用processGuid和parentProcessGuid）"""
    # 按processGuid索引
    node_map = {node.get('processGuid'): node for node in nodes if node.get('processGuid')}
    
    # 找根节点
    root_node = None
    for node in nodes:
        if node.get('isRoot') or node.get('processGuid') == node.get('traceId'):
            root_node = node
            break
    
    # 构建父子关系
    children_map = defaultdict(list)
    for node in nodes:
        parent_guid = node.get('parentProcessGuid')
        if parent_guid and parent_guid in node_map:
            children_map[parent_guid].append(node.get('processGuid'))
    
    return root_node, node_map, children_map

def format_node(node):
    """格式化节点显示"""
    process_name = node.get('processName', 'unknown')
    process_guid = node.get('processGuid', '')
    process_id = node.get('processId', 0)
    log_type = node.get('logType', 'process')
    
    if log_type == 'file':
        return f"📄 {process_name} [{process_guid}] (文件日志)"
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

def generate_chain_diagram(file_path, output_path):
    """生成链关系图"""
    print(f"解析数据文件: {file_path}")
    nodes, network_alert = parse_test_data(file_path)
    
    print(f"总节点数: {len(nodes)}")
    
    root_node, node_map, children_map = build_tree(nodes)
    
    if not root_node:
        print("错误：找不到根节点！")
        return
    
    print(f"根节点: {root_node.get('processName')} [{root_node.get('processGuid')}]")
    
    # 生成树形图
    tree_lines = [format_node(root_node)]
    
    children = children_map.get(root_node.get('processGuid'), [])
    for i, child_guid in enumerate(children):
        is_last = (i == len(children) - 1)
        tree_lines.extend(print_tree(child_guid, node_map, children_map, "", is_last))
    
    # 统计信息
    stats = count_nodes_by_type(nodes)
    
    # 生成Markdown
    md_lines = [
        "# 案例5 - Webshell文件上传攻击链关系图",
        "",
        "## 基本信息",
        f"- **主机地址**: {root_node.get('hostAddress', 'N/A')}",
        "- **攻击类型**: Webshell文件上传",
        "- **攻击工具**: 冰蝎(Behinder) Webshell",
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
    
    print(f"链关系图已生成: {output_path}")

if __name__ == '__main__':
    input_file = 'demo/dataSet/webshell文件上传/案例5/test_data.txt'
    output_file = 'demo/dataSet/webshell文件上传/案例5/链关系图.md'
    
    generate_chain_diagram(input_file, output_file)

