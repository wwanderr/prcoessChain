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
     * @param targetIp 目标 IP 地址（focusIp 中的某一个，用于精确修正）
     * @return Pair 对象，key 为修正后的节点列表，value 为修正后的边列表
     */
    public static Pair<List<ProcessNode>, List<ProcessEdge>> correctNodeRoles(
            List<ProcessNode> nodes, 
            List<ProcessEdge> edges, 
            RiskIncident incident,
            String targetIp) {
        
        if (incident == null || incident.getFocusObject() == null) {
            log.info("【角色修正】无需修正：incident 信息不完整");
            return Pair.of(nodes, edges);
        }
        
        if (targetIp == null || targetIp.trim().isEmpty()) {
            log.info("【角色修正】无需修正：targetIp 为空");
            return Pair.of(nodes, edges);
        }
        
        String focusObject = incident.getFocusObject().trim().toLowerCase();
        String targetIpTrimmed = targetIp.trim();
        
        // 验证 focusObject 是否为 attacker 或 victim
        if (!focusObject.equals("attacker") && !focusObject.equals("victim")) {
            log.warn("【角色修正】无效的 focusObject: {}，仅支持 attacker 或 victim", focusObject);
            return Pair.of(nodes, edges);
        }
        
        log.info("【角色修正】开始修正，focusObject={}, targetIp={}", focusObject, targetIpTrimmed);
        
        // 1. 记录 nodeId 变化映射（oldNodeId -> newNodeId）
        Map<String, String> nodeIdMapping = new HashMap<>();
        
        // 记录已修正的节点ID（用于后续反向修正相连节点）
        Set<String> correctedNodeIds = new HashSet<>();
        
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
            
            // 检查该 IP 是否匹配 targetIp
            if (!targetIpTrimmed.equalsIgnoreCase(nodeIp.trim())) {
                continue; // 不是目标 IP，跳过
            }
            
            // ✅ 关键条件：只修正源节点（srcNode）
            // destNode（目标节点）即使在 focusIp 中也不修正
            String storyNodeType = node.getStoryNode().getType();
            if (storyNodeType == null || !"srcNode".equals(storyNodeType)) {
                log.debug("【角色修正】跳过非源节点：ip={}, storyNodeType={}", nodeIp, storyNodeType);
                continue;
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
            
            // 记录已修正的节点ID（用于后续反向修正）
            correctedNodeIds.add(newNodeId);
            
            correctedCount++;
        }
        
        // 3. 修正边的引用
        if (!nodeIdMapping.isEmpty()) {
            correctEdges(edges, nodeIdMapping);
        }
        
        log.info("【角色修正-第一阶段】修正焦点节点完成：共修正 {} 个节点，更新 {} 条边引用", 
                correctedCount, nodeIdMapping.size());
        
        // 4. 反向修正与修正节点相连的节点
        // 如果 targetIp 节点有问题被修正了，相连的所有 attacker/victim 都要反向修正
        int reverseCorrectCount = 0;
        Set<String> reverseCorrectedNodeIds = new HashSet<>();  // 记录已被反向修正的节点
        if (!correctedNodeIds.isEmpty()) {
            reverseCorrectCount = correctConnectedNodes(nodes, edges, correctedNodeIds, 
                    targetIpTrimmed, reverseCorrectedNodeIds);
        }
        
        log.info("【角色修正-第二阶段】通过边关系反向修正：{}个节点", reverseCorrectCount);
        
        // 5. 处理孤立的特殊节点（assetAddress 等无边连接的节点）
        // 只处理那些没有被第4步修正到的节点
        int isolatedCorrectCount = 0;
        if (correctedCount > 0) {
            isolatedCorrectCount = correctIsolatedSpecialNodes(nodes, edges, focusObject, 
                    targetIpTrimmed, reverseCorrectedNodeIds);
        }
        
        log.info("【角色修正-完成】焦点节点修正={}个，关联节点反向修正={}个，孤立节点修正={}个", 
                correctedCount, reverseCorrectCount, isolatedCorrectCount);
        
        // 6. 返回修正后的节点和边
        return Pair.of(nodes, edges);
    }
    
    /**
     * 反向修正与已修正节点相连的节点
     * 
     * 逻辑：
     * 1. 找到所有与已修正节点相连的节点（通过边关系）
     * 2. 如果相连节点的角色是 attacker 或 victim，则反向修正
     * 3. 只排除 targetIp 本身（避免循环修正）
     * 
     * 重要规则：如果 targetIp 节点有问题被修正了，与它相连的所有 attacker/victim 节点
     * 都应该反向修正，无论这些节点是否在 focusIp 列表中
     * 
     * @param nodes 所有节点
     * @param edges 所有边
     * @param correctedNodeIds 已修正的节点ID集合
     * @param targetIp 目标IP（只排除它自己，避免循环修正）
     * @param reverseCorrectedNodeIds 输出参数：记录被反向修正的节点ID
     * @return 反向修正的节点数量
     */
    private static int correctConnectedNodes(
            List<ProcessNode> nodes,
            List<ProcessEdge> edges,
            Set<String> correctedNodeIds,
            String targetIp,
            Set<String> reverseCorrectedNodeIds) {
        
        // 1. 找到所有与已修正节点相连的节点ID
        Set<String> connectedNodeIds = new HashSet<>();
        
        for (ProcessEdge edge : edges) {
            if (edge == null) {
                continue;
            }
            
            // 如果 source 是已修正的节点，则 target 是相连节点
            if (correctedNodeIds.contains(edge.getSource())) {
                connectedNodeIds.add(edge.getTarget());
            }
            
            // 如果 target 是已修正的节点，则 source 是相连节点
            if (correctedNodeIds.contains(edge.getTarget())) {
                connectedNodeIds.add(edge.getSource());
            }
        }
        
        log.info("【反向修正】找到 {} 个与修正节点相连的节点", connectedNodeIds.size());
        
        // 2. 创建 nodeId 到 node 的映射，方便查找
        Map<String, ProcessNode> nodeMap = new HashMap<>();
        for (ProcessNode node : nodes) {
            if (node != null && node.getNodeId() != null) {
                nodeMap.put(node.getNodeId(), node);
            }
        }
        
        // 3. 反向修正相连节点
        int reverseCorrectCount = 0;
        
        for (String connectedNodeId : connectedNodeIds) {
            ProcessNode connectedNode = nodeMap.get(connectedNodeId);
            
            if (connectedNode == null) {
                continue;
            }
            
            // 提取节点 IP
            String nodeIp = extractIpFromNode(connectedNode);
            
            // ✅ 只排除 targetIp 本身（避免循环修正）
            // 如果 targetIp 有问题被修正了，其他所有相连的 attacker/victim 都要反向修正
            if (nodeIp != null && targetIp.equalsIgnoreCase(nodeIp.trim())) {
                log.debug("【反向修正】跳过目标IP节点本身：nodeId={}, ip={}", connectedNodeId, nodeIp);
                continue;
            }
            
            // 获取当前角色
            String currentLogType = connectedNode.getLogType();
            if (currentLogType == null) {
                continue;
            }
            
            String currentRole = currentLogType.trim().toLowerCase();
            
            // 只反向修正 attacker 和 victim
            if (!currentRole.equals("attacker") && !currentRole.equals("victim")) {
                log.debug("【反向修正】跳过非 attacker/victim 节点：nodeId={}, logType={}", 
                        connectedNodeId, currentLogType);
                continue;
            }
            
            // 反向角色
            String reverseRole = currentRole.equals("attacker") ? "victim" : "attacker";
            
            log.info("【反向修正】修正节点角色：nodeId={}, {} -> {}", 
                    connectedNodeId, currentRole, reverseRole);
            
            // 修正节点
            correctNode(connectedNode, reverseRole, nodeIp);
            
            // 记录已被反向修正的节点ID
            reverseCorrectedNodeIds.add(connectedNodeId);
            
            reverseCorrectCount++;
        }
        
        log.info("【反向修正】完成：共反向修正 {} 个节点", reverseCorrectCount);
        
        return reverseCorrectCount;
    }
    
    /**
     * 修正孤立的特殊节点（没有边连接的节点）
     * 
     * 逻辑：
     * 1. 只处理 assetAddress 等特殊类型的节点
     * 2. 只处理那些没有被 correctConnectedNodes 修正到的节点（孤立节点）
     * 3. 只处理没有任何边连接的节点（真正的孤立节点）
     * 4. 反向修正这些节点的角色
     * 
     * 场景：如果 attacker 变成 victim，但原有的 victim 节点是 assetAddress 类型且没有边，
     * 则应该将这个 victim 反向修正为 attacker
     * 
     * @param nodes 所有节点
     * @param edges 所有边
     * @param newRole 修正后的角色（attacker 或 victim）
     * @param targetIp 目标IP
     * @param alreadyCorrectedNodeIds 已经被修正的节点ID集合（用于排除）
     * @return 修正的节点数量
     */
    private static int correctIsolatedSpecialNodes(
            List<ProcessNode> nodes,
            List<ProcessEdge> edges,
            String newRole,
            String targetIp,
            Set<String> alreadyCorrectedNodeIds) {
        
        // 确定对立角色
        String oppositeRole = newRole.equals("attacker") ? "victim" : "attacker";
        
        // 1. 找出所有有边连接的节点（有任何边连接就不是孤立节点）
        Set<String> nodesWithEdges = new HashSet<>();
        if (edges != null) {
            for (ProcessEdge edge : edges) {
                if (edge != null) {
                    if (edge.getSource() != null) {
                        nodesWithEdges.add(edge.getSource());
                    }
                    if (edge.getTarget() != null) {
                        nodesWithEdges.add(edge.getTarget());
                    }
                }
            }
        }
        
        log.debug("【孤立节点】有边连接的节点数量：{}", nodesWithEdges.size());
        
        int correctedCount = 0;
        
        // 2. 遍历节点，找到孤立的特殊节点
        for (ProcessNode node : nodes) {
            if (node == null || node.getStoryNode() == null) {
                continue;
            }
            
            String nodeId = node.getNodeId();
            if (nodeId == null) {
                continue;
            }
            
            // ✅ 关键检查1：如果节点已经被反向修正过，跳过
            if (alreadyCorrectedNodeIds != null && alreadyCorrectedNodeIds.contains(nodeId)) {
                log.debug("【孤立节点】跳过已修正节点：nodeId={}", nodeId);
                continue;
            }
            
            // ✅ 关键检查2：如果节点有边连接，跳过（不是孤立节点）
            if (nodesWithEdges.contains(nodeId)) {
                log.debug("【孤立节点】跳过有边连接的节点：nodeId={}", nodeId);
                continue;
            }
            
            // 检查节点类型（只处理 assetAddress 等特殊类型）
            String storyNodeType = node.getStoryNode().getType();
            if (!"assetAddress".equals(storyNodeType)) {
                continue;
            }
            
            // 检查当前角色
            String currentLogType = node.getLogType();
            if (currentLogType == null) {
                continue;
            }
            
            String currentRole = currentLogType.trim().toLowerCase();
            
            // 只处理 attacker 和 victim
            if (!currentRole.equals("attacker") && !currentRole.equals("victim")) {
                continue;
            }
            
            // 只处理当前角色是 oppositeRole 的节点
            if (!currentRole.equals(oppositeRole)) {
                log.debug("【孤立节点】跳过角色不匹配的节点：nodeId={}, currentRole={}, oppositeRole={}", 
                        nodeId, currentRole, oppositeRole);
                continue;
            }
            
            // 提取 IP
            String nodeIp = extractIpFromNode(node);
            
            // 排除 targetIp 本身
            if (nodeIp != null && targetIp != null && targetIp.equalsIgnoreCase(nodeIp.trim())) {
                log.debug("【孤立节点】跳过目标IP节点：nodeId={}, ip={}", nodeId, nodeIp);
                continue;
            }
            
            // ✅ 找到了孤立的 assetAddress 节点，进行反向修正
            log.info("【孤立节点修正】修正无边连接的 {} 节点：nodeId={}, {} -> {}", 
                    storyNodeType, nodeId, currentRole, newRole);
            
            correctNode(node, newRole, nodeIp);
            correctedCount++;
        }
        
        log.info("【孤立节点修正】完成：共修正 {} 个孤立节点", correctedCount);
        
        return correctedCount;
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

