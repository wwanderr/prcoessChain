package com.security.processchain.util;

import com.security.processchain.model.ProcessEdge;
import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RiskIncident;
import com.security.processchain.service.StoryNode;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.stream.Collectors;

/**
 * 网侧节点角色修正工具
 * 
 * 用于解决网侧和端侧桥接时的角色混淆问题：
 * - 根据 focusIp 和 focusObject 判断节点的真实角色
 * - 修正节点的 logType、nodeId、storyNode 等字段
 * - 修正边的 source/target 引用
 * 
 * 规则：
 * 1. 只修正 attacker/victim 角色，其他类型（server、dnsServer 等）不受影响
 * 2. 如果节点 IP 在 focusIp 列表中，且当前角色与 focusObject 不一致，则修正
 * 3. nodeId 规则：角色名会更新为新角色，IP 地址保持不变
 * 4. 不修改 isTopNode 属性
 */
@Slf4j
public class NetworkNodeRoleCorrector {
    
    /**
     * 修正网侧节点角色
     * 
     * @param nodes 节点列表
     * @param edges 边列表
     * @param incident 风险事件（包含 focusIp 和 focusObject）
     */
    public static void correctNodeRoles(
            List<ProcessNode> nodes, 
            List<ProcessEdge> edges, 
            RiskIncident incident) {
        
        if (incident == null || incident.getFocusObject() == null || incident.getFocusIp() == null) {
            log.info("【角色修正】无需修正：incident 信息不完整");
            return;
        }
        
        String focusObject = incident.getFocusObject().trim().toLowerCase();
        List<String> focusIpList = incident.getFocusIpList().stream()
                .map(String::trim)
                .collect(Collectors.toList());
        
        if (focusIpList.isEmpty()) {
            log.info("【角色修正】无需修正：focusIp 列表为空");
            return;
        }
        
        // 验证 focusObject 是否为 attacker 或 victim
        if (!focusObject.equals("attacker") && !focusObject.equals("victim")) {
            log.warn("【角色修正】无效的 focusObject: {}，仅支持 attacker 或 victim", focusObject);
            return;
        }
        
        log.info("【角色修正】开始修正，focusObject={}, focusIpList={}", focusObject, focusIpList);
        
        // 1. 记录 nodeId 变化映射（oldNodeId -> newNodeId）
        Map<String, String> nodeIdMapping = new HashMap<>();
        
        // 2. 遍历节点，修正角色
        int correctedCount = 0;
        for (ProcessNode node : nodes) {
            if (node == null || node.getStoryNode() == null) {
                continue;
            }
            
            // 提取节点的 IP 地址
            String nodeIp = extractIpFromNode(node);
            if (nodeIp == null) {
                continue;
            }
            
            // 检查该 IP 是否在 focusIp 列表中
            boolean isFocusIp = focusIpList.stream()
                    .anyMatch(ip -> ip.equalsIgnoreCase(nodeIp.trim()));
            
            if (!isFocusIp) {
                continue; // 不在 focus_ip 中，跳过
            }
            
            // 获取当前节点的角色
            String currentLogType = node.getLogType();
            if (currentLogType == null) {
                continue;
            }
            
            String currentRole = currentLogType.trim().toLowerCase();
            
            // 只处理 attacker 和 victim 的角色互换
            if (!currentRole.equals("attacker") && !currentRole.equals("victim")) {
                log.debug("【角色修正】跳过非 attacker/victim 节点：ip={}, logType={}", 
                        nodeIp, currentLogType);
                continue;
            }
            
            // 检查是否需要修正
            if (currentRole.equals(focusObject)) {
                log.debug("【角色修正】节点角色已正确：ip={}, logType={}", nodeIp, currentLogType);
                continue;
            }
            
            // 需要修正：当前角色与 focusObject 不一致
            String oldNodeId = node.getNodeId();
            String newRole = focusObject; // 应该是的角色
            
            log.info("【角色修正】修正节点角色：ip={}, {} -> {}, oldNodeId={}", 
                    nodeIp, currentRole, newRole, oldNodeId);
            
            // 修正节点
            correctNode(node, newRole, nodeIp);
            
            // 记录 nodeId 变化
            String newNodeId = node.getNodeId();
            if (!oldNodeId.equals(newNodeId)) {
                nodeIdMapping.put(oldNodeId, newNodeId);
                log.debug("【角色修正】nodeId 变化：{} -> {}", oldNodeId, newNodeId);
            }
            
            correctedCount++;
        }
        
        // 3. 修正边的引用
        if (!nodeIdMapping.isEmpty()) {
            correctEdges(edges, nodeIdMapping);
        }
        
        log.info("【角色修正】修正完成：共修正 {} 个节点，更新 {} 条边引用", 
                correctedCount, nodeIdMapping.size());
    }
    
    /**
     * 从节点中提取 IP 地址
     * 
     * @param node 节点
     * @return IP 地址，如果不存在则返回 null
     */
    private static String extractIpFromNode(ProcessNode node) {
        if (node.getStoryNode() == null || node.getStoryNode().getNode() == null) {
            return null;
        }
        
        Map<String, Object> nodeData = node.getStoryNode().getNode();
        Object ipObj = nodeData.get("ip");
        
        if (ipObj != null) {
            return ipObj.toString().trim();
        }
        
        // 尝试从 ips 数组中获取（某些节点可能有 ips 字段）
        Object ipsObj = nodeData.get("ips");
        if (ipsObj instanceof List) {
            List<?> ipsList = (List<?>) ipsObj;
            if (!ipsList.isEmpty() && ipsList.get(0) != null) {
                return ipsList.get(0).toString().trim();
            }
        }
        
        return null;
    }
    
    /**
     * 修正单个节点
     * 
     * @param node 节点
     * @param newRole 新角色（"attacker" 或 "victim"）
     * @param nodeIp 节点 IP
     */
    private static void correctNode(ProcessNode node, String newRole, String nodeIp) {
        String oldLogType = node.getLogType();
        String oldNodeId = node.getNodeId();
        
        // 1. 修正 logType
        node.setLogType(newRole);
        
        // 2. 修正 nodeId
        // 规则：如果原来 nodeId 是角色名（attacker/victim），则改为新角色名
        //      如果原来 nodeId 是 IP，保持 IP 不变
        String newNodeId;
        if (oldNodeId.equalsIgnoreCase("attacker") || oldNodeId.equalsIgnoreCase("victim")) {
            newNodeId = newRole;
        } else {
            // 保持原 nodeId（通常是 IP 地址）
            newNodeId = oldNodeId;
        }
        node.setNodeId(newNodeId);
        
        // 3. 修正 storyNode.node.type
        StoryNode storyNode = node.getStoryNode();
        if (storyNode != null && storyNode.getNode() != null) {
            Map<String, Object> nodeData = storyNode.getNode();
            nodeData.put("type", newRole);
            
            // 4. 修正 storyNode.node.name（如果存在）
            if (nodeData.containsKey("name")) {
                String oldName = nodeData.get("name") != null ? nodeData.get("name").toString() : "";
                String newName = getRoleName(newRole);
                nodeData.put("name", newName);
                log.debug("【角色修正】修正 name：{} -> {}", oldName, newName);
            }
            
            // 5. 修正其他可能包含角色信息的字段
            // 如果有其他字段需要修正，可以在这里添加
        }
        
        log.debug("【角色修正】节点修正完成：logType={}->{}, nodeId={}->{}", 
                oldLogType, newRole, oldNodeId, newNodeId);
    }
    
    /**
     * 获取角色的中文名称
     * 
     * @param role 角色（attacker 或 victim）
     * @return 中文名称
     */
    private static String getRoleName(String role) {
        switch (role.toLowerCase()) {
            case "attacker":
                return "攻击者";
            case "victim":
                return "受害者";
            default:
                return role;
        }
    }
    
    /**
     * 修正边的引用
     * 
     * @param edges 边列表
     * @param nodeIdMapping nodeId 变化映射（oldNodeId -> newNodeId）
     */
    private static void correctEdges(List<ProcessEdge> edges, Map<String, String> nodeIdMapping) {
        if (edges == null || edges.isEmpty()) {
            return;
        }
        
        int updatedCount = 0;
        
        for (ProcessEdge edge : edges) {
            if (edge == null) {
                continue;
            }
            
            boolean updated = false;
            
            // 更新 source
            if (edge.getSource() != null && nodeIdMapping.containsKey(edge.getSource())) {
                String oldSource = edge.getSource();
                String newSource = nodeIdMapping.get(oldSource);
                edge.setSource(newSource);
                log.debug("【边修正】source: {} -> {}", oldSource, newSource);
                updated = true;
            }
            
            // 更新 target
            if (edge.getTarget() != null && nodeIdMapping.containsKey(edge.getTarget())) {
                String oldTarget = edge.getTarget();
                String newTarget = nodeIdMapping.get(oldTarget);
                edge.setTarget(newTarget);
                log.debug("【边修正】target: {} -> {}", oldTarget, newTarget);
                updated = true;
            }
            
            if (updated) {
                updatedCount++;
            }
        }
        
        log.info("【边修正】共更新 {} 条边", updatedCount);
    }
}

