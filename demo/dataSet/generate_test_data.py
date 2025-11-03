#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试数据生成脚本
用于生成所有测试案例的数据文件
"""

import json
import os
import random
from datetime import datetime, timedelta

# 配置
SCENARIOS = {
    "webshell文件上传": {
        "cases": {
            5: {"layers": 8, "nodes": 120, "branches": 3, "ip": "10.50.113.196", "traceId": "traceId-989", "vendor": "TrendMicro"}
        },
        "network_rule": "检测到上传冰蝎webshell文件(PHP)",
        "network_type": "/WebAttack/WebshellUpload",
        "incident": "Webshell后门访问事件"
    },
    "命令执行": {
        "cases": {
            2: {"layers": 5, "nodes": 12, "branches": 0, "ip": "10.50.114.197", "traceId": "traceId-212", "vendor": "McAfee"},
            3: {"layers": 6, "nodes": 22, "branches": 2, "ip": "10.50.115.198", "traceId": "traceId-213", "vendor": "Sophos"},
            4: {"layers": 7, "nodes": 35, "branches": 0, "ip": "10.50.116.199", "traceId": "traceId-214", "vendor": "ESET"},
            5: {"layers": 8, "nodes": 110, "branches": 3, "ip": "10.50.117.200", "traceId": "traceId-215", "vendor": "Bitdefender"}
        },
        "network_rule": "通用命令执行攻击",
        "network_type": "/WebAttack/CommandExec",
        "incident": "命令执行攻击事件"
    },
    "矿池": {
        "cases": {
            2: {"layers": 5, "nodes": 10, "branches": 0, "ip": "10.50.118.201", "traceId": "traceId-206", "vendor": "Avast"},
            3: {"layers": 6, "nodes": 20, "branches": 2, "ip": "10.50.119.202", "traceId": "traceId-207", "vendor": "AVG"},
            4: {"layers": 7, "nodes": 38, "branches": 0, "ip": "10.50.120.203", "traceId": "traceId-208", "vendor": "Panda"},
            5: {"layers": 8, "nodes": 115, "branches": 3, "ip": "10.50.121.204", "traceId": "traceId-209", "vendor": "Comodo"}
        },
        "network_rule": "Symmi家族挖矿软件回连活动事件",
        "network_type": "/Malware/Miner",
        "incident": "Symmi恶意家族活动事件"
    }
}

# 进程名称库
PROCESS_NAMES = {
    "webshell文件上传": ["php-cgi.exe", "xp.cn_cgi.exe", "phpstudy_pro.exe", "apache.exe", "nginx.exe", "RuntimeBroker.exe", "svchost.exe", "services.exe", "wininit.exe", "lsass.exe", "explorer.exe", "cmd.exe", "powershell.exe", "conhost.exe", "dllhost.exe"],
    "命令执行": ["whoami.exe", "cmd.exe", "powershell.exe", "php-cgi.exe", "nginx.exe", "net.exe", "reg.exe", "sc.exe", "svchost.exe", "services.exe", "wininit.exe", "explorer.exe", "taskmgr.exe", "regedit.exe", "mmc.exe"],
    "矿池": ["MsCpuCN64.exe", "powershell.exe", "cmd.exe", "svchost.exe", "explorer.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "services.exe", "wininit.exe", "taskhost.exe", "dwm.exe", "csrss.exe"]
}

def generate_guid():
    """生成随机GUID"""
    return ''.join(random.choices('0123456789ABCDEF', k=16))

def generate_md5():
    """生成随机MD5"""
    return ''.join(random.choices('0123456789abcdef', k=32))

def generate_network_data(scenario, config, case_num):
    """生成网侧告警数据"""
    src_ip = f"10.50.86.{150 + case_num}"
    
    network = {
        "sendHostAddress": "10.50.86.14",
        "srcAddress": src_ip,
        "destAddress": config["ip"],
        "destPort": "80" if scenario != "矿池" else "53",
        "logType": "alert",
        "severity": "7",
        "confidence": "High",
        "ruleName": SCENARIOS[scenario]["network_rule"],
        "ruleType": SCENARIOS[scenario]["network_type"],
        "incidentName": SCENARIOS[scenario]["incident"],
        "tacticId": "TA0001",
        "techniquesId": "T1190",
        "startTime": "2025-05-23 15:31:06",
        "@timestamp": "2025-05-23T07:31:06.000Z",
        "direction": "00",
        "netId": "7effcbb7-0c7a-4da9-bde1-32d06166acae",
        "srcOrgId": "7effcbb7-0c7a-4da9-bde1-32d06166acae",
        "destOrgId": "7effcbb7-0c7a-4da9-bde1-32d06166acae",
        "message": f"{SCENARIOS[scenario]['network_rule']}. 来源：{src_ip}, 目的：{config['ip']}"
    }
    
    return json.dumps(network, ensure_ascii=False)

def calculate_nodes_per_layer(total_nodes, layers, has_branches):
    """计算每层的节点数"""
    nodes_per_layer = []
    
    if not has_branches:
        # 线性链：平均分配
        avg = total_nodes // layers
        remainder = total_nodes % layers
        for i in range(layers):
            nodes_per_layer.append(avg + (1 if i < remainder else 0))
    else:
        # 分支链：指数增长
        nodes_per_layer.append(1)  # 根节点
        remaining = total_nodes - 1
        
        for i in range(1, layers):
            if i == layers - 1:
                nodes_per_layer.append(remaining)
            else:
                # 逐层增加节点数
                factor = 1.5 ** i
                nodes = max(1, int(remaining * factor / sum([1.5 ** j for j in range(1, layers)])))
                nodes = min(nodes, remaining)
                nodes_per_layer.append(nodes)
                remaining -= nodes
    
    return nodes_per_layer

def generate_endpoint_data(scenario, config, case_num):
    """生成端侧进程链数据"""
    nodes = []
    nodes_per_layer = calculate_nodes_per_layer(config["nodes"], config["layers"], config["branches"] > 0)
    
    process_names = PROCESS_NAMES[scenario]
    base_time = datetime(2025, 5, 21, 10, 0, 0)
    
    # 生成所有节点
    node_id = 1000
    guid_map = {}  # 存储每层的GUID，用于父子关系
    
    for layer in range(config["layers"]):
        layer_guids = []
        nodes_in_layer = nodes_per_layer[layer]
        
        for i in range(nodes_in_layer):
            # 确定父节点
            if layer == 0:
                guid = config["traceId"]
                parent_guid = None if i == 0 else guid_map.get(layer - 1, [None])[0]
            else:
                guid = generate_guid()
                # 从上一层随机选择父节点
                parent_guids = guid_map.get(layer - 1, [])
                if parent_guids:
                    if config["branches"] > 0 and layer > 1:
                        # 分支场景：随机选择父节点
                        parent_guid = random.choice(parent_guids)
                    else:
                        # 线性场景：按顺序选择
                        parent_guid = parent_guids[min(i, len(parent_guids) - 1)]
                else:
                    parent_guid = None
            
            layer_guids.append(guid)
            
            # 选择进程名
            process_name = process_names[min(layer, len(process_names) - 1)]
            
            # 生成节点数据
            node = {
                "processGuid": guid,
                "parentProcessGuid": parent_guid,
                "processName": process_name,
                "processId": node_id,
                "parentProcessId": node_id - 1 if parent_guid else 0,
                "commandLine": f"{process_name}",
                "image": f"C:\\Windows\\System32\\{process_name}",
                "processMd5": generate_md5(),
                "processUserName": "DESKTOP-M0S0L3H\\Administrator" if layer < 3 else "SYSTEM",
                "processStartTime": (base_time + timedelta(minutes=layer, seconds=i * 10)).strftime("%Y-%m-%d %H:%M:%S"),
                "logType": "file" if layer == 0 and i == 0 else "process",
                "opType": "create",
                "hostAddress": config["ip"],
                "srcAddress": config["ip"],
                "destAddress": config["ip"],
                "severity": 7 if layer == 0 and i == 0 else 0,
                "confidence": "High" if layer == 0 and i == 0 else None,
                "productVendorName": config["vendor"],
                "traceId": config["traceId"],
                "direction": "00",
                "netId": "7effcbb7-0c7a-4da9-bde1-32d06166acae",
                "srcOrgId": "7effcbb7-0c7a-4da9-bde1-32d06166acae",
                "destOrgId": "7effcbb7-0c7a-4da9-bde1-32d06166acae",
                "@timestamp": (base_time + timedelta(minutes=layer, seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
            }
            
            # 添加文件相关字段（仅第一个节点）
            if layer == 0 and i == 0:
                node["fileName"] = "malware.php" if scenario == "webshell文件上传" else "evil.exe"
                node["targetFilename"] = f"C:\\temp\\{node['fileName']}"
            
            nodes.append(node)
            node_id += 1
        
        guid_map[layer] = layer_guids
    
    return [json.dumps(node, ensure_ascii=False) for node in nodes]

def generate_case(scenario, case_num, config):
    """生成单个案例的数据文件"""
    case_dir = f"{scenario}/案例{case_num}"
    os.makedirs(case_dir, exist_ok=True)
    
    file_path = f"{case_dir}/test_data.txt"
    
    with open(file_path, 'w', encoding='utf-8') as f:
        # 第1行：网侧数据
        network_data = generate_network_data(scenario, config, case_num)
        f.write(network_data + '\n')
        
        # 后续行：端侧数据
        endpoint_data_list = generate_endpoint_data(scenario, config, case_num)
        for endpoint_data in endpoint_data_list:
            f.write(endpoint_data + '\n')
    
    print(f"[OK] 生成 {scenario}/案例{case_num}: {config['layers']}层, {config['nodes']}节点 -> {file_path}")

def main():
    """主函数"""
    print("=" * 60)
    print("开始生成测试数据...")
    print("=" * 60)
    
    for scenario, scenario_config in SCENARIOS.items():
        print(f"\n【{scenario}】场景:")
        for case_num, config in scenario_config["cases"].items():
            generate_case(scenario, case_num, config)
    
    print("\n" + "=" * 60)
    print("所有测试数据生成完成！")
    print("=" * 60)

if __name__ == "__main__":
    main()

