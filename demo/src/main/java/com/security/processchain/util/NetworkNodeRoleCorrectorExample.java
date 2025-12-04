package com.security.processchain.util;

import com.security.processchain.model.ProcessEdge;
import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RiskIncident;
import com.security.processchain.service.StoryNode;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * 网侧节点角色修正使用示例
 * 
 * 演示如何使用 NetworkNodeRoleCorrector 修正节点角色
 */
@Slf4j
public class NetworkNodeRoleCorrectorExample {
    
    /**
     * 示例1：修正 victim 被错误标记为 attacker 的情况
     */
    public static void example1_correctVictimMislabeledAsAttacker() {
        log.info("=== 示例1：修正 victim 被错误标记为 attacker ===");
        
        // 1. 创建风险事件信息
        RiskIncident incident = new RiskIncident();
        incident.setFocusIp("10.50.86.136");
        incident.setFocusObject("victim");
        
        // 2. 构建节点列表（模拟从数据源获取）
        List<ProcessNode> nodes = new ArrayList<>();
        
        // 攻击者节点（错误：应该是受害者）
        ProcessNode attackerNode = new ProcessNode();
        attackerNode.setLogType("attacker");
        attackerNode.setNodeId("attacker");
        attackerNode.setIsChainNode(false);
        
        StoryNode attackerStory = new StoryNode();
        attackerStory.setType("srcNode");
        Map<String, Object> attackerData = new HashMap<>();
        attackerData.put("port", "65518");
        attackerData.put("ip", "10.50.86.136");
        attackerData.put("describe", "关联");
        attackerData.put("type", "attacker");
        attackerStory.setNode(attackerData);
        attackerNode.setStoryNode(attackerStory);
        
        nodes.add(attackerNode);
        
        // 服务器节点（正确，不需要修改）
        ProcessNode serverNode = new ProcessNode();
        serverNode.setLogType("server");
        serverNode.setNodeId("server");
        serverNode.setIsChainNode(false);
        
        StoryNode serverStory = new StoryNode();
        serverStory.setType("destNode");
        Map<String, Object> serverData = new HashMap<>();
        serverData.put("name", "矿池");
        serverData.put("describe", "关联");
        serverData.put("type", "server");
        serverStory.setNode(serverData);
        serverNode.setStoryNode(serverStory);
        
        nodes.add(serverNode);
        
        // 3. 构建边列表
        List<ProcessEdge> edges = new ArrayList<>();
        ProcessEdge edge = new ProcessEdge();
        edge.setSource("attacker");
        edge.setTarget("server");
        edge.setVal("访问恶意IP：10.50.86.136");
        edges.add(edge);
        
        // 4. 打印修正前的状态
        log.info("修正前：");
        printNodesAndEdges(nodes, edges);
        
        // 5. 执行修正
        NetworkNodeRoleCorrector.correctNodeRoles(nodes, edges, incident);
        
        // 6. 打印修正后的状态
        log.info("修正后：");
        printNodesAndEdges(nodes, edges);
    }
    
    /**
     * 示例2：修正 attacker 被错误标记为 victim 的情况
     */
    public static void example2_correctAttackerMislabeledAsVictim() {
        log.info("=== 示例2：修正 attacker 被错误标记为 victim ===");
        
        // 1. 创建风险事件信息
        RiskIncident incident = new RiskIncident();
        incident.setFocusIp("10.50.109.192");
        incident.setFocusObject("attacker");
        
        // 2. 构建节点列表
        List<ProcessNode> nodes = new ArrayList<>();
        
        // 受害者节点（错误：应该是攻击者）
        ProcessNode victimNode = new ProcessNode();
        victimNode.setLogType("victim");
        victimNode.setNodeId("10.50.109.192");
        victimNode.setIsChainNode(false);
        
        StoryNode victimStory = new StoryNode();
        victimStory.setType("srcNode");
        Map<String, Object> victimData = new HashMap<>();
        victimData.put("ip", "10.50.109.192");
        victimData.put("describe", "关联");
        victimData.put("type", "victim");
        victimStory.setNode(victimData);
        victimNode.setStoryNode(victimStory);
        
        nodes.add(victimNode);
        
        // 目标攻击者节点
        ProcessNode targetNode = new ProcessNode();
        targetNode.setLogType("attacker");
        targetNode.setNodeId("10.50.86.46");
        targetNode.setIsChainNode(false);
        
        StoryNode targetStory = new StoryNode();
        targetStory.setType("destNode");
        Map<String, Object> targetData = new HashMap<>();
        targetData.put("terminalCount", 52);
        targetData.put("port", "445");
        targetData.put("ip", "10.50.86.46");
        targetData.put("describe", "关联");
        targetData.put("type", "attacker");
        targetStory.setNode(targetData);
        targetNode.setStoryNode(targetStory);
        
        nodes.add(targetNode);
        
        // 3. 构建边列表
        List<ProcessEdge> edges = new ArrayList<>();
        ProcessEdge edge = new ProcessEdge();
        edge.setSource("10.50.109.192");
        edge.setTarget("10.50.86.46");
        edge.setVal("");
        edges.add(edge);
        
        // 4. 打印修正前的状态
        log.info("修正前：");
        printNodesAndEdges(nodes, edges);
        
        // 5. 执行修正
        NetworkNodeRoleCorrector.correctNodeRoles(nodes, edges, incident);
        
        // 6. 打印修正后的状态
        log.info("修正后：");
        printNodesAndEdges(nodes, edges);
    }
    
    /**
     * 示例3：多个 focusIp 的情况
     */
    public static void example3_multipleFocusIps() {
        log.info("=== 示例3：多个 focusIp 的情况 ===");
        
        // 1. 创建风险事件信息（多个 IP）
        RiskIncident incident = new RiskIncident();
        incident.setFocusIp("10.20.152.227,10.50.24.4,10.20.152.228,10.20.152.225");
        incident.setFocusObject("victim");
        
        // 2. 构建节点列表
        List<ProcessNode> nodes = new ArrayList<>();
        
        // 添加多个错误标记的节点
        for (String ip : incident.getFocusIpList()) {
            ProcessNode node = new ProcessNode();
            node.setLogType("attacker"); // 错误：应该是 victim
            node.setNodeId(ip);
            node.setIsChainNode(false);
            
            StoryNode story = new StoryNode();
            story.setType("srcNode");
            Map<String, Object> data = new HashMap<>();
            data.put("ip", ip);
            data.put("type", "attacker");
            story.setNode(data);
            node.setStoryNode(story);
            
            nodes.add(node);
        }
        
        List<ProcessEdge> edges = new ArrayList<>();
        
        // 3. 打印修正前的状态
        log.info("修正前：");
        printNodesAndEdges(nodes, edges);
        
        // 4. 执行修正
        NetworkNodeRoleCorrector.correctNodeRoles(nodes, edges, incident);
        
        // 5. 打印修正后的状态
        log.info("修正后：");
        printNodesAndEdges(nodes, edges);
    }
    
    /**
     * 打印节点和边的信息
     */
    private static void printNodesAndEdges(List<ProcessNode> nodes, List<ProcessEdge> edges) {
        log.info("节点列表：");
        for (ProcessNode node : nodes) {
            String ip = node.getStoryNode() != null && node.getStoryNode().getNode() != null
                    ? (String) node.getStoryNode().getNode().get("ip")
                    : "N/A";
            log.info("  - nodeId={}, logType={}, ip={}, type={}", 
                    node.getNodeId(), 
                    node.getLogType(),
                    ip,
                    node.getStoryNode() != null && node.getStoryNode().getNode() != null
                            ? node.getStoryNode().getNode().get("type")
                            : "N/A");
        }
        
        log.info("边列表：");
        for (ProcessEdge edge : edges) {
            log.info("  - {} -> {}: {}", edge.getSource(), edge.getTarget(), edge.getVal());
        }
    }
    
    /**
     * 运行所有示例
     */
    public static void main(String[] args) {
        // 运行示例1
        example1_correctVictimMislabeledAsAttacker();
        log.info("");
        
        // 运行示例2
        example2_correctAttackerMislabeledAsVictim();
        log.info("");
        
        // 运行示例3
        example3_multipleFocusIps();
    }
}

