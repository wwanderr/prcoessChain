package com.security.processchain;

import com.security.processchain.model.ProcessEdge;
import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RiskIncident;
import com.security.processchain.service.StoryNode;
import com.security.processchain.util.NetworkNodeRoleCorrector;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 网侧节点角色修正测试
 */
public class NetworkNodeRoleCorrectorTest {
    
    @Test
    @DisplayName("场景1：victim 被错误标记为 attacker - 应修正为 victim")
    public void testCorrectVictimMislabeledAsAttacker() {
        // 准备数据
        RiskIncident incident = new RiskIncident();
        incident.setFocusIp("10.50.86.136");
        incident.setFocusObject("victim");
        
        // 创建节点
        List<ProcessNode> nodes = new ArrayList<>();
        
        // 攻击者节点（实际应该是受害者）
        ProcessNode attackerNode = createNode("attacker", "attacker", "10.50.86.136", "攻击者");
        nodes.add(attackerNode);
        
        // 服务器节点
        ProcessNode serverNode = createNode("server", "server", null, "矿池");
        nodes.add(serverNode);
        
        // 创建边
        List<ProcessEdge> edges = new ArrayList<>();
        ProcessEdge edge = new ProcessEdge();
        edge.setSource("attacker");
        edge.setTarget("server");
        edge.setVal("访问恶意IP：10.50.86.136");
        edges.add(edge);
        
        // 执行修正
        NetworkNodeRoleCorrector.correctNodeRoles(nodes, edges, incident);
        
        // 验证节点修正
        assertEquals("victim", attackerNode.getLogType(), "logType 应该被修正为 victim");
        assertEquals("victim", attackerNode.getNodeId(), "nodeId 应该被修正为 victim");
        assertEquals("victim", attackerNode.getStoryNode().getNode().get("type"), "type 应该被修正为 victim");
        assertEquals("受害者", attackerNode.getStoryNode().getNode().get("name"), "name 应该被修正为受害者");
        
        // 验证服务器节点未被修改
        assertEquals("server", serverNode.getLogType(), "server 节点不应该被修改");
        
        // 验证边修正
        assertEquals("victim", edges.get(0).getSource(), "边的 source 应该被更新为 victim");
        assertEquals("server", edges.get(0).getTarget(), "边的 target 应该保持为 server");
    }
    
    @Test
    @DisplayName("场景2：attacker 被错误标记为 victim - 应修正为 attacker")
    public void testCorrectAttackerMislabeledAsVictim() {
        // 准备数据
        RiskIncident incident = new RiskIncident();
        incident.setFocusIp("10.50.109.192");
        incident.setFocusObject("attacker");
        
        // 创建节点
        List<ProcessNode> nodes = new ArrayList<>();
        
        // 受害者节点（实际应该是攻击者）
        ProcessNode victimNode = createNode("victim", "10.50.109.192", "10.50.109.192", "受害者");
        nodes.add(victimNode);
        
        // 目标节点
        ProcessNode targetNode = createNode("attacker", "10.50.86.46", "10.50.86.46", "攻击者");
        nodes.add(targetNode);
        
        // 创建边
        List<ProcessEdge> edges = new ArrayList<>();
        ProcessEdge edge = new ProcessEdge();
        edge.setSource("10.50.109.192");
        edge.setTarget("10.50.86.46");
        edges.add(edge);
        
        // 执行修正
        NetworkNodeRoleCorrector.correctNodeRoles(nodes, edges, incident);
        
        // 验证节点修正
        assertEquals("attacker", victimNode.getLogType(), "logType 应该被修正为 attacker");
        assertEquals("10.50.109.192", victimNode.getNodeId(), "nodeId 应该保持为 IP 地址");
        assertEquals("attacker", victimNode.getStoryNode().getNode().get("type"), "type 应该被修正为 attacker");
        assertEquals("攻击者", victimNode.getStoryNode().getNode().get("name"), "name 应该被修正为攻击者");
        
        // 验证目标节点未被修改（因为不在 focusIp 中）
        assertEquals("attacker", targetNode.getLogType(), "目标节点不应该被修改");
        
        // 验证边（nodeId 是 IP 地址，所以不会变化）
        assertEquals("10.50.109.192", edges.get(0).getSource(), "边的 source 应该保持为 IP");
        assertEquals("10.50.86.46", edges.get(0).getTarget(), "边的 target 应该保持不变");
    }
    
    @Test
    @DisplayName("场景3：多个 focusIp 的情况")
    public void testMultipleFocusIps() {
        // 准备数据
        RiskIncident incident = new RiskIncident();
        incident.setFocusIp("10.50.86.197,10.50.109.192");
        incident.setFocusObject("attacker");
        
        // 创建节点
        List<ProcessNode> nodes = new ArrayList<>();
        
        // 第一个错误标记的节点
        ProcessNode victim1 = createNode("victim", "10.50.86.197", "10.50.86.197", "受害者");
        nodes.add(victim1);
        
        // 第二个错误标记的节点
        ProcessNode victim2 = createNode("victim", "10.50.109.192", "10.50.109.192", "受害者");
        nodes.add(victim2);
        
        // 执行修正
        NetworkNodeRoleCorrector.correctNodeRoles(nodes, edges, incident);
        
        // 验证两个节点都被修正
        assertEquals("attacker", victim1.getLogType(), "第一个节点应该被修正");
        assertEquals("attacker", victim2.getLogType(), "第二个节点应该被修正");
    }
    
    @Test
    @DisplayName("场景4：节点角色已正确 - 不应修正")
    public void testNoCorrectNeeded() {
        // 准备数据
        RiskIncident incident = new RiskIncident();
        incident.setFocusIp("10.50.86.136");
        incident.setFocusObject("victim");
        
        // 创建节点（角色已正确）
        List<ProcessNode> nodes = new ArrayList<>();
        ProcessNode victimNode = createNode("victim", "victim", "10.50.86.136", "受害者");
        nodes.add(victimNode);
        
        List<ProcessEdge> edges = new ArrayList<>();
        
        // 执行修正
        NetworkNodeRoleCorrector.correctNodeRoles(nodes, edges, incident);
        
        // 验证节点未被修改
        assertEquals("victim", victimNode.getLogType(), "角色正确的节点不应该被修改");
        assertEquals("victim", victimNode.getNodeId(), "nodeId 不应该被修改");
    }
    
    @Test
    @DisplayName("场景5：非 attacker/victim 节点 - 不应修正")
    public void testNonAttackerVictimNodeNotCorrected() {
        // 准备数据
        RiskIncident incident = new RiskIncident();
        incident.setFocusIp("10.50.86.136");
        incident.setFocusObject("victim");
        
        // 创建节点
        List<ProcessNode> nodes = new ArrayList<>();
        ProcessNode serverNode = createNode("server", "server", "10.50.86.136", "矿池");
        nodes.add(serverNode);
        
        List<ProcessEdge> edges = new ArrayList<>();
        
        // 执行修正
        NetworkNodeRoleCorrector.correctNodeRoles(nodes, edges, incident);
        
        // 验证服务器节点未被修改
        assertEquals("server", serverNode.getLogType(), "server 节点不应该被修改");
    }
    
    @Test
    @DisplayName("场景6：incident 为 null - 应安全返回")
    public void testNullIncident() {
        List<ProcessNode> nodes = new ArrayList<>();
        List<ProcessEdge> edges = new ArrayList<>();
        
        // 不应该抛出异常
        assertDoesNotThrow(() -> {
            NetworkNodeRoleCorrector.correctNodeRoles(nodes, edges, null);
        });
    }
    
    @Test
    @DisplayName("场景7：focusIp 为空 - 应安全返回")
    public void testEmptyFocusIp() {
        RiskIncident incident = new RiskIncident();
        incident.setFocusIp("");
        incident.setFocusObject("victim");
        
        List<ProcessNode> nodes = new ArrayList<>();
        List<ProcessEdge> edges = new ArrayList<>();
        
        // 不应该抛出异常
        assertDoesNotThrow(() -> {
            NetworkNodeRoleCorrector.correctNodeRoles(nodes, edges, incident);
        });
    }
    
    /**
     * 创建测试节点
     */
    private ProcessNode createNode(String logType, String nodeId, String ip, String name) {
        ProcessNode node = new ProcessNode();
        node.setLogType(logType);
        node.setNodeId(nodeId);
        node.setIsChainNode(false);
        
        StoryNode storyNode = new StoryNode();
        storyNode.setType("srcNode");
        
        Map<String, Object> nodeData = new HashMap<>();
        if (ip != null) {
            nodeData.put("ip", ip);
        }
        nodeData.put("type", logType);
        if (name != null) {
            nodeData.put("name", name);
        }
        
        storyNode.setNode(nodeData);
        node.setStoryNode(storyNode);
        
        return node;
    }
}

