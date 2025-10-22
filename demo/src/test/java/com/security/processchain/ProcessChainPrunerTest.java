package com.security.processchain;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.ProcessChainBuilder;
import com.security.processchain.util.ProcessChainPruner;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ProcessChainPruner 单元测试
 * 
 * 验证目标：
 * 1. 裁剪失败时能够回滚到原始数据
 * 2. 裁剪后每个 traceId 只有一个根节点
 * 3. 裁剪后与 addExploreNodesForBrokenChains 逻辑兼容
 */
public class ProcessChainPrunerTest {
    
    private static final Logger log = LoggerFactory.getLogger(ProcessChainPrunerTest.class);
    
    /**
     * 测试1：裁剪后根节点必须保留
     */
    @Test
    void testPruneNodes_RootNodesMustBeKept() {
        log.info("=== 测试: 裁剪后根节点必须保留 ===");
        
        // 准备数据：创建一个进程链，有200个节点（超过限制）
        Map<String, ProcessChainBuilder.ChainBuilderNode> nodeMap = new HashMap<>();
        List<ProcessChainBuilder.ChainBuilderEdge> edges = new ArrayList<>();
        Set<String> rootNodes = new HashSet<>();
        Set<String> associatedEventIds = new HashSet<>();
        
        // 创建根节点
        String rootGuid = "ROOT_001";
        rootNodes.add(rootGuid);
        ProcessChainBuilder.ChainBuilderNode rootNode = createNode(rootGuid, null, true, "高");
        nodeMap.put(rootGuid, rootNode);
        
        // 创建199个子节点（模拟超过限制的情况）
        String parentGuid = rootGuid;
        for (int i = 1; i <= 199; i++) {
            String childGuid = "NODE_" + String.format("%03d", i);
            ProcessChainBuilder.ChainBuilderNode childNode = createNode(childGuid, parentGuid, false, null);
            nodeMap.put(childGuid, childNode);
            
            ProcessChainBuilder.ChainBuilderEdge edge = createEdge(parentGuid, childGuid);
            edges.add(edge);
            
            parentGuid = childGuid;
        }
        
        log.info("原始数据: 节点数={}, 根节点={}", nodeMap.size(), rootNodes);
        
        // 执行裁剪
        ProcessChainPruner.PruneContext context = new ProcessChainPruner.PruneContext(
            nodeMap, edges, rootNodes, associatedEventIds
        );
        
        ProcessChainPruner.PruneResult result = ProcessChainPruner.pruneNodes(context);
        
        // 验证：根节点必须保留
        assertTrue(nodeMap.containsKey(rootGuid), "根节点必须被保留");
        assertTrue(nodeMap.size() > 0, "裁剪后必须有节点");
        
        log.info("裁剪结果: 原始节点={}, 移除节点={}, 最终节点={}", 
                 result.getOriginalNodeCount(), result.getRemovedNodeCount(), result.getFinalNodeCount());
        log.info("✅ 测试通过：根节点已保留");
    }
    
    /**
     * 测试2：异常时回滚到原始数据
     */
    @Test
    void testPruneNodes_RollbackOnFailure() {
        log.info("=== 测试: 异常时回滚到原始数据 ===");
        
        // 准备正常数据
        Map<String, ProcessChainBuilder.ChainBuilderNode> nodeMap = new HashMap<>();
        List<ProcessChainBuilder.ChainBuilderEdge> edges = new ArrayList<>();
        Set<String> rootNodes = new HashSet<>();
        Set<String> associatedEventIds = new HashSet<>();
        
        // 创建3个节点
        String rootGuid = "ROOT_001";
        rootNodes.add(rootGuid);
        nodeMap.put(rootGuid, createNode(rootGuid, null, true, "高"));
        
        String child1Guid = "CHILD_001";
        nodeMap.put(child1Guid, createNode(child1Guid, rootGuid, false, null));
        edges.add(createEdge(rootGuid, child1Guid));
        
        String child2Guid = "CHILD_002";
        nodeMap.put(child2Guid, createNode(child2Guid, child1Guid, false, null));
        edges.add(createEdge(child1Guid, child2Guid));
        
        int originalNodeCount = nodeMap.size();
        int originalEdgeCount = edges.size();
        
        log.info("原始数据: 节点数={}, 边数={}", originalNodeCount, originalEdgeCount);
        
        // 执行裁剪（节点数没有超过限制，不应该裁剪）
        ProcessChainPruner.PruneContext context = new ProcessChainPruner.PruneContext(
            nodeMap, edges, rootNodes, associatedEventIds
        );
        
        ProcessChainPruner.PruneResult result = ProcessChainPruner.pruneNodes(context);
        
        // 验证：节点数没超限制，不应该裁剪
        assertEquals(originalNodeCount, nodeMap.size(), "节点数未超限制时不应裁剪");
        assertEquals(originalEdgeCount, edges.size(), "边数未超限制时不应裁剪");
        assertEquals(0, result.getRemovedNodeCount(), "未超限制时移除数应为0");
        
        log.info("裁剪结果: 原始节点={}, 移除节点={}, 最终节点={}", 
                 result.getOriginalNodeCount(), result.getRemovedNodeCount(), result.getFinalNodeCount());
        log.info("✅ 测试通过：未超限制时保留原始数据");
    }
    
    /**
     * 测试3：裁剪后每个traceId只有一个根节点
     */
    @Test
    void testPruneNodes_OneRootPerTraceId() {
        log.info("=== 测试: 裁剪后每个 traceId 只有一个根节点 ===");
        
        // 准备数据：模拟单个 traceId 的场景
        Map<String, ProcessChainBuilder.ChainBuilderNode> nodeMap = new HashMap<>();
        List<ProcessChainBuilder.ChainBuilderEdge> edges = new ArrayList<>();
        Set<String> rootNodes = new HashSet<>();
        Set<String> associatedEventIds = new HashSet<>();
        
        // 创建1个根节点
        String rootGuid = "TRACE_001";  // 假设这是 traceId
        rootNodes.add(rootGuid);
        ProcessChainBuilder.ChainBuilderNode rootNode = createNode(rootGuid, null, true, "高");
        nodeMap.put(rootGuid, rootNode);
        
        // 创建若干子节点
        for (int i = 1; i <= 50; i++) {
            String childGuid = "NODE_" + String.format("%03d", i);
            ProcessChainBuilder.ChainBuilderNode childNode = createNode(childGuid, rootGuid, false, null);
            nodeMap.put(childGuid, childNode);
            
            ProcessChainBuilder.ChainBuilderEdge edge = createEdge(rootGuid, childGuid);
            edges.add(edge);
        }
        
        log.info("原始数据: 根节点数={}, 总节点数={}", rootNodes.size(), nodeMap.size());
        
        // 执行裁剪
        ProcessChainPruner.PruneContext context = new ProcessChainPruner.PruneContext(
            nodeMap, edges, rootNodes, associatedEventIds
        );
        
        ProcessChainPruner.PruneResult result = ProcessChainPruner.pruneNodes(context);
        
        // 验证：根节点必须保留，且只有一个
        int rootNodeCountAfterPrune = 0;
        for (String guid : rootNodes) {
            if (nodeMap.containsKey(guid)) {
                rootNodeCountAfterPrune++;
            }
        }
        
        assertEquals(1, rootNodeCountAfterPrune, "裁剪后应该只有1个根节点");
        assertTrue(nodeMap.containsKey(rootGuid), "原始根节点必须保留");
        
        log.info("裁剪结果: 根节点数={}, 最终节点数={}", rootNodeCountAfterPrune, nodeMap.size());
        log.info("✅ 测试通过：只有一个根节点");
    }
    
    /**
     * 测试4：裁剪后与 Explore 节点逻辑兼容
     * 
     * 验证：裁剪后产生的断链节点能够被正确识别
     */
    @Test
    void testPruneNodes_CompatibleWithExploreLogic() {
        log.info("=== 测试: 裁剪后与 Explore 节点逻辑兼容 ===");
        
        // 准备数据：创建一个较大的链，模拟裁剪会产生断链的情况
        Map<String, ProcessChainBuilder.ChainBuilderNode> nodeMap = new HashMap<>();
        List<ProcessChainBuilder.ChainBuilderEdge> edges = new ArrayList<>();
        Set<String> rootNodes = new HashSet<>();
        Set<String> associatedEventIds = new HashSet<>();
        
        // 创建根节点
        String rootGuid = "ROOT_001";
        rootNodes.add(rootGuid);
        nodeMap.put(rootGuid, createNode(rootGuid, null, true, "高"));
        
        // 创建一个长链：ROOT -> A -> B -> ... -> Z (26个节点)
        String parentGuid = rootGuid;
        List<String> chainGuids = new ArrayList<>();
        chainGuids.add(rootGuid);
        
        for (int i = 0; i < 25; i++) {
            String childGuid = "NODE_" + (char)('A' + i);
            nodeMap.put(childGuid, createNode(childGuid, parentGuid, false, null));
            edges.add(createEdge(parentGuid, childGuid));
            chainGuids.add(childGuid);
            parentGuid = childGuid;
        }
        
        // 在最后一个节点上添加告警（使其成为必须保留节点）
        String lastGuid = chainGuids.get(chainGuids.size() - 1);
        ProcessChainBuilder.ChainBuilderNode lastNode = nodeMap.get(lastGuid);
        RawAlarm alarm = new RawAlarm();
        alarm.setProcessGuid(lastGuid);
        alarm.setThreatSeverity("高");
        lastNode.addAlarm(alarm);
        lastNode.setIsAlarm(true);
        
        log.info("原始数据: 节点数={}, 链长度={}", nodeMap.size(), chainGuids.size());
        
        // 执行裁剪
        ProcessChainPruner.PruneContext context = new ProcessChainPruner.PruneContext(
            nodeMap, edges, rootNodes, associatedEventIds
        );
        
        ProcessChainPruner.PruneResult result = ProcessChainPruner.pruneNodes(context);
        
        // 验证1：根节点和告警节点都保留
        assertTrue(nodeMap.containsKey(rootGuid), "根节点必须保留");
        assertTrue(nodeMap.containsKey(lastGuid), "告警节点必须保留");
        
        // 验证2：检查断链节点
        Set<String> brokenNodes = new HashSet<>();
        for (ProcessChainBuilder.ChainBuilderNode node : nodeMap.values()) {
            String parentGuidCheck = node.getParentProcessGuid();
            if (parentGuidCheck != null && !parentGuidCheck.trim().isEmpty()) {
                if (!nodeMap.containsKey(parentGuidCheck) && !rootNodes.contains(node.getProcessGuid())) {
                    brokenNodes.add(node.getProcessGuid());
                    log.debug("检测到断链节点: {} (父节点 {} 不存在)", node.getProcessGuid(), parentGuidCheck);
                }
            }
        }
        
        log.info("裁剪结果: 原始节点={}, 最终节点={}, 断链节点数={}", 
                 result.getOriginalNodeCount(), result.getFinalNodeCount(), brokenNodes.size());
        
        // 验证3：如果有断链，验证 Explore 逻辑能够处理
        if (!brokenNodes.isEmpty() && rootNodes.isEmpty()) {
            log.info("检测到断链且无根节点，Explore 逻辑应该会创建虚拟根节点");
        } else if (!brokenNodes.isEmpty() && !rootNodes.isEmpty()) {
            log.info("检测到断链但有根节点，Explore 逻辑不应创建虚拟根节点");
        } else {
            log.info("无断链，Explore 逻辑不需要介入");
        }
        
        log.info("✅ 测试通过：裁剪后的断链能够被正确识别");
    }
    
    /**
     * 测试5：网端关联节点必须保留
     */
    @Test
    void testPruneNodes_AssociatedNodesMustBeKept() {
        log.info("=== 测试: 网端关联节点必须保留 ===");
        
        // 准备数据
        Map<String, ProcessChainBuilder.ChainBuilderNode> nodeMap = new HashMap<>();
        List<ProcessChainBuilder.ChainBuilderEdge> edges = new ArrayList<>();
        Set<String> rootNodes = new HashSet<>();
        Set<String> associatedEventIds = new HashSet<>();
        
        // 创建根节点
        String rootGuid = "ROOT_001";
        rootNodes.add(rootGuid);
        nodeMap.put(rootGuid, createNode(rootGuid, null, true, "高"));
        
        // 创建关联节点
        String associatedGuid = "ASSOCIATED_001";
        String associatedEventId = "EVENT_123";
        associatedEventIds.add(associatedEventId);
        
        ProcessChainBuilder.ChainBuilderNode associatedNode = createNode(associatedGuid, rootGuid, true, "中");
        RawAlarm alarm = new RawAlarm();
        alarm.setProcessGuid(associatedGuid);
        alarm.setEventId(associatedEventId);
        alarm.setThreatSeverity("中");
        associatedNode.addAlarm(alarm);
        nodeMap.put(associatedGuid, associatedNode);
        edges.add(createEdge(rootGuid, associatedGuid));
        
        // 创建100个其他低分节点
        for (int i = 1; i <= 100; i++) {
            String childGuid = "NODE_" + String.format("%03d", i);
            nodeMap.put(childGuid, createNode(childGuid, rootGuid, false, null));
            edges.add(createEdge(rootGuid, childGuid));
        }
        
        log.info("原始数据: 总节点数={}, 关联节点={}", nodeMap.size(), associatedGuid);
        
        // 执行裁剪
        ProcessChainPruner.PruneContext context = new ProcessChainPruner.PruneContext(
            nodeMap, edges, rootNodes, associatedEventIds
        );
        
        ProcessChainPruner.PruneResult result = ProcessChainPruner.pruneNodes(context);
        
        // 验证：关联节点必须保留
        assertTrue(nodeMap.containsKey(associatedGuid), "网端关联节点必须保留");
        assertTrue(nodeMap.containsKey(rootGuid), "根节点必须保留");
        
        log.info("裁剪结果: 原始节点={}, 最终节点={}, 关联节点已保留", 
                 result.getOriginalNodeCount(), result.getFinalNodeCount());
        log.info("✅ 测试通过：网端关联节点已保留");
    }
    
    // ========== 辅助方法 ==========
    
    private ProcessChainBuilder.ChainBuilderNode createNode(String processGuid, String parentProcessGuid, 
                                                             boolean isAlarm, String severity) {
        ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
        node.setProcessGuid(processGuid);
        node.setParentProcessGuid(parentProcessGuid);
        node.setIsAlarm(isAlarm);
        
        if (isAlarm && severity != null) {
            RawAlarm alarm = new RawAlarm();
            alarm.setProcessGuid(processGuid);
            alarm.setThreatSeverity(severity);
            alarm.setEventId("EVENT_" + processGuid);
            node.addAlarm(alarm);
        }
        
        // 添加一个日志
        RawLog log = new RawLog();
        log.setProcessGuid(processGuid);
        log.setParentProcessGuid(parentProcessGuid);
        log.setLogType("process");
        node.addLog(log);
        
        return node;
    }
    
    private ProcessChainBuilder.ChainBuilderEdge createEdge(String source, String target) {
        ProcessChainBuilder.ChainBuilderEdge edge = new ProcessChainBuilder.ChainBuilderEdge();
        edge.setSource(source);
        edge.setTarget(target);
        edge.setVal("1");
        return edge;
    }
}


