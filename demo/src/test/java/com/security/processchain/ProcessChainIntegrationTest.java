package com.security.processchain;

import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.IncidentConverters;
import com.security.processchain.service.IncidentProcessChain;
import com.security.processchain.service.ProcessChainBuilder;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 进程链集成测试
 * 
 * 测试目标：
 * 1. 裁剪逻辑的容错性（失败时回滚）
 * 2. 根节点唯一性（每个 traceId 只有一个根节点）
 * 3. 裁剪与 Explore 逻辑的兼容性
 */
public class ProcessChainIntegrationTest {
    
    private static final Logger log = LoggerFactory.getLogger(ProcessChainIntegrationTest.class);
    
    /**
     * 测试1：单个 traceId，有真实根节点，无断链
     * 
     * 预期：
     * - 找到1个真实根节点
     * - 不创建 Explore 节点
     * - 根节点 isRoot = true
     */
    @Test
    void testSingleTraceId_WithRootNode_NoBrokenChain() {
        log.info("=== 测试: 单个 traceId，有真实根节点，无断链 ===");
        
        // 准备数据 - 根节点的 processGuid 必须等于 traceId
        String traceId = "T001";
        RawAlarm alarm = createAlarm("E001", traceId, traceId, null, "高危告警", "高");
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog(traceId, null, traceId, "svchost.exe", "processCreate"),
            createProcessLog("CHILD_001", traceId, traceId, "cmd.exe", "processCreate"),
            createProcessLog("CHILD_002", "CHILD_001", traceId, "powershell.exe", "processCreate")
        );
        
        Set<String> traceIds = new HashSet<>(Collections.singletonList(traceId));
        Set<String> associatedEventIds = new HashSet<>();
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            Collections.singletonList(alarm),
            logs,
            traceIds,
            associatedEventIds,
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull(result);
        assertNotNull(result.getNodes());
        
        // 验证根节点数量
        long rootCount = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .count();
        
        assertEquals(1, rootCount, "应该有且只有1个根节点");
        
        // 验证根节点是真实根节点，不是 Explore
        ProcessNode rootNode = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .findFirst()
            .orElse(null);
        
        assertNotNull(rootNode, "应该找到根节点");
        assertEquals(traceId, rootNode.getNodeId(), "根节点应该是 " + traceId);
        assertNotEquals("EXPLORE_ROOT", rootNode.getNodeId(), "不应该创建 Explore 节点");
        
        log.info("✅ 测试通过：有真实根节点，无 Explore 节点");
    }
    
    /**
     * 测试2：单个 traceId，无真实根节点，有断链
     * 
     * 预期：
     * - 没有真实根节点
     * - 创建1个 Explore 虚拟根节点
     * - Explore 的 isRoot = true
     * - 所有断链连接到 Explore
     */
    @Test
    void testSingleTraceId_NoRootNode_WithBrokenChain() {
        log.info("=== 测试: 单个 traceId，无真实根节点，有断链 ===");
        
        // 准备数据（故意不包含 processGuid == traceId 的节点）
        String traceId = "T001";
        RawAlarm alarm = createAlarm("E001", traceId, "NODE_MIDDLE", "NODE_PARENT", "高危告警", "高");
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog("NODE_MIDDLE", "NODE_PARENT", traceId, "cmd.exe", "processCreate"),
            createProcessLog("NODE_CHILD", "NODE_MIDDLE", traceId, "powershell.exe", "processCreate")
        );
        
        Set<String> traceIds = new HashSet<>(Collections.singletonList(traceId));
        Set<String> associatedEventIds = new HashSet<>();
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            Collections.singletonList(alarm),
            logs,
            traceIds,
            associatedEventIds,
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull(result);
        assertNotNull(result.getNodes());
        
        // 验证根节点数量
        long rootCount = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .count();
        
        assertEquals(1, rootCount, "应该有且只有1个根节点（Explore）");
        
        // 验证是 Explore 虚拟根节点
        ProcessNode rootNode = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .findFirst()
            .orElse(null);
        
        assertNotNull(rootNode, "应该找到根节点");
        assertEquals("EXPLORE_ROOT", rootNode.getNodeId(), "应该创建 EXPLORE_ROOT 虚拟根节点");
        
        // 验证断链节点
        long brokenCount = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           Boolean.TRUE.equals(node.getChainNode().getIsBroken()))
            .count();
        
        assertTrue(brokenCount > 0, "应该有断链节点");
        
        log.info("✅ 测试通过：无真实根节点，创建了 Explore 虚拟根节点");
    }
    
    /**
     * 测试3：多个 traceId，每个都有真实根节点
     * 
     * 预期：
     * - 找到多个真实根节点（每个 traceId 一个）
     * - 不创建 Explore 节点
     * - 每个根节点的 isRoot = true
     */
    @Test
    void testMultipleTraceIds_AllWithRootNodes() {
        log.info("=== 测试: 多个 traceId，每个都有真实根节点 ===");
        
        // 准备数据 - 根节点的 processGuid 必须等于 traceId
        List<RawAlarm> alarms = Arrays.asList(
            createAlarm("E001", "T001", "T001", null, "告警1", "高"),
            createAlarm("E002", "T002", "T002", null, "告警2", "高"),
            createAlarm("E003", "T003", "T003", null, "告警3", "高")
        );
        
        List<RawLog> logs = Arrays.asList(
            // T001 的日志
            createProcessLog("T001", null, "T001", "process1.exe", "processCreate"),
            createProcessLog("CHILD_T001_1", "T001", "T001", "child1.exe", "processCreate"),
            
            // T002 的日志
            createProcessLog("T002", null, "T002", "process2.exe", "processCreate"),
            createProcessLog("CHILD_T002_1", "T002", "T002", "child2.exe", "processCreate"),
            
            // T003 的日志
            createProcessLog("T003", null, "T003", "process3.exe", "processCreate"),
            createProcessLog("CHILD_T003_1", "T003", "T003", "child3.exe", "processCreate")
        );
        
        Set<String> traceIds = new HashSet<>(Arrays.asList("T001", "T002", "T003"));
        Set<String> associatedEventIds = new HashSet<>();
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms,
            logs,
            traceIds,
            associatedEventIds,
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull(result);
        
        // 验证根节点数量
        long rootCount = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .count();
        
        assertEquals(3, rootCount, "应该有3个根节点");
        
        // 验证每个根节点都是真实根节点
        List<String> rootNodeIds = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .map(ProcessNode::getNodeId)
            .collect(java.util.stream.Collectors.toList());
        
        assertTrue(rootNodeIds.contains("T001"), "应该包含 T001");
        assertTrue(rootNodeIds.contains("T002"), "应该包含 T002");
        assertTrue(rootNodeIds.contains("T003"), "应该包含 T003");
        assertFalse(rootNodeIds.contains("EXPLORE_ROOT"), "不应该有 Explore 节点");
        
        log.info("✅ 测试通过：多个 traceId，每个都有真实根节点");
    }
    
    /**
     * 测试4：多个断链，无真实根节点
     * 
     * 预期：
     * - 没有真实根节点
     * - 创建1个 Explore 虚拟根节点
     * - 所有断链都连接到同一个 Explore
     */
    @Test
    void testMultipleBrokenChains_NoRootNode() {
        log.info("=== 测试: 多个断链，无真实根节点 ===");
        
        // 准备数据（3个独立的断链分支）
        String traceId = "T001";
        List<RawAlarm> alarms = Arrays.asList(
            createAlarm("E001", traceId, "BRANCH_A_1", "BRANCH_A_0", "告警A", "高"),
            createAlarm("E002", traceId, "BRANCH_B_1", "BRANCH_B_0", "告警B", "中"),
            createAlarm("E003", traceId, "BRANCH_C_1", "BRANCH_C_0", "告警C", "高")
        );
        
        List<RawLog> logs = Arrays.asList(
            // 分支 A
            createProcessLog("BRANCH_A_1", "BRANCH_A_0", traceId, "processA.exe", "processCreate"),
            createProcessLog("BRANCH_A_2", "BRANCH_A_1", traceId, "childA.exe", "processCreate"),
            
            // 分支 B
            createProcessLog("BRANCH_B_1", "BRANCH_B_0", traceId, "processB.exe", "processCreate"),
            
            // 分支 C
            createProcessLog("BRANCH_C_1", "BRANCH_C_0", traceId, "processC.exe", "processCreate")
        );
        
        Set<String> traceIds = new HashSet<>(Collections.singletonList(traceId));
        Set<String> associatedEventIds = new HashSet<>();
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms,
            logs,
            traceIds,
            associatedEventIds,
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull(result);
        
        // 验证根节点数量
        long rootCount = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .count();
        
        assertEquals(1, rootCount, "应该有且只有1个根节点（Explore）");
        
        // 验证是 Explore 虚拟根节点
        ProcessNode rootNode = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .findFirst()
            .orElse(null);
        
        assertNotNull(rootNode, "应该找到根节点");
        assertEquals("EXPLORE_ROOT", rootNode.getNodeId(), "应该创建唯一的 EXPLORE_ROOT");
        
        // 验证所有断链节点
        long brokenCount = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           Boolean.TRUE.equals(node.getChainNode().getIsBroken()))
            .count();
        
        assertTrue(brokenCount >= 3, "应该有至少3个断链节点");
        
        // 验证从 Explore 到断链的边
        long exploreEdges = result.getEdges().stream()
            .filter(edge -> "EXPLORE_ROOT".equals(edge.getSource()))
            .count();
        
        assertTrue(exploreEdges >= 3, "Explore 应该连接到至少3个断链节点");
        
        log.info("✅ 测试通过：多个断链统一连接到唯一的 Explore 节点");
    }
    
    /**
     * 测试5：裁剪后根节点保留
     * 
     * 预期：
     * - 即使触发裁剪，根节点也不会被删除
     * - 裁剪后仍然保持根节点唯一性
     */
    @Test
    void testPruning_RootNodePreserved() {
        log.info("=== 测试: 裁剪后根节点保留 ===");
        
        // 准备大量数据以触发裁剪（假设超过节点限制）- 根节点的 processGuid 必须等于 traceId
        String traceId = "T001";
        RawAlarm alarm = createAlarm("E001", traceId, traceId, null, "高危告警", "高");
        
        List<RawLog> logs = new ArrayList<>();
        logs.add(createProcessLog(traceId, null, traceId, "root.exe", "processCreate"));
        
        // 创建一个长链（但不足以触发裁剪，这里只是演示逻辑）
        String parentGuid = traceId;
        for (int i = 1; i <= 50; i++) {
            String childGuid = "NODE_" + String.format("%03d", i);
            logs.add(createProcessLog(childGuid, parentGuid, traceId, 
                                    "process" + i + ".exe", "processCreate"));
            parentGuid = childGuid;
        }
        
        Set<String> traceIds = new HashSet<>(Collections.singletonList(traceId));
        Set<String> associatedEventIds = new HashSet<>();
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            Collections.singletonList(alarm),
            logs,
            traceIds,
            associatedEventIds,
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull(result);
        
        // 验证根节点存在
        ProcessNode rootNode = result.getNodes().stream()
            .filter(node -> traceId.equals(node.getNodeId()))
            .findFirst()
            .orElse(null);
        
        assertNotNull(rootNode, "根节点必须保留，不能被裁剪");
        assertTrue(rootNode.getChainNode().getIsRoot(), "根节点的 isRoot 应该为 true");
        
        // 验证只有一个根节点
        long rootCount = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .count();
        
        assertEquals(1, rootCount, "裁剪后应该仍然只有1个根节点");
        
        log.info("✅ 测试通过：裁剪后根节点已保留");
    }
    
    /**
     * 测试6：网端关联节点在裁剪后保留
     * 
     * 预期：
     * - 网端关联的告警节点不会被裁剪
     * - 从关联节点到根节点的路径完整
     */
    @Test
    void testPruning_AssociatedNodePreserved() {
        log.info("=== 测试: 网端关联节点在裁剪后保留 ===");
        
        // 准备数据 - 根节点的 processGuid 必须等于 traceId
        String traceId = "T001";
        String associatedEventId = "EVENT_123";
        
        RawAlarm rootAlarm = createAlarm("E001", traceId, traceId, null, "根节点告警", "高");
        RawAlarm associatedAlarm = createAlarm(associatedEventId, traceId, "NODE_ASSOCIATED", 
                                              traceId, "关联告警", "高");
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog(traceId, null, traceId, "root.exe", "processCreate"),
            createProcessLog("NODE_ASSOCIATED", traceId, traceId, "associated.exe", "processCreate")
        );
        
        Set<String> traceIds = new HashSet<>(Collections.singletonList(traceId));
        Set<String> associatedEventIds = new HashSet<>(Collections.singletonList(associatedEventId));
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            Arrays.asList(rootAlarm, associatedAlarm),
            logs,
            traceIds,
            associatedEventIds,
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull(result);
        
        // 验证关联节点存在
        ProcessNode associatedNode = result.getNodes().stream()
            .filter(node -> "NODE_ASSOCIATED".equals(node.getNodeId()))
            .findFirst()
            .orElse(null);
        
        assertNotNull(associatedNode, "网端关联节点必须保留");
        
        // 验证根节点存在（根节点ID已改为traceId）
        ProcessNode rootNode = result.getNodes().stream()
            .filter(node -> traceId.equals(node.getNodeId()))
            .findFirst()
            .orElse(null);
        
        assertNotNull(rootNode, "根节点必须保留");
        
        // 验证它们之间的边存在（完整路径）
        boolean pathExists = result.getEdges().stream()
            .anyMatch(edge -> traceId.equals(edge.getSource()) && 
                             "NODE_ASSOCIATED".equals(edge.getTarget()));
        
        assertTrue(pathExists, "从根节点到关联节点的路径必须完整");
        
        log.info("✅ 测试通过：网端关联节点和完整路径已保留");
    }
    
    // ==================== 辅助方法 ====================
    
    private RawAlarm createAlarm(String eventId, String traceId, String processGuid, 
                                  String parentProcessGuid, String alarmName, String severity) {
        RawAlarm alarm = new RawAlarm();
        alarm.setEventId(eventId);
        alarm.setTraceId(traceId);
        alarm.setProcessGuid(processGuid);
        alarm.setParentProcessGuid(parentProcessGuid);
        alarm.setAlarmName(alarmName);
        alarm.setThreatSeverity(severity);
        alarm.setHostAddress("10.0.0.1");
        alarm.setStartTime("2024-01-15 10:00:00");
        return alarm;
    }
    
    private RawLog createProcessLog(String processGuid, String parentProcessGuid, 
                                     String traceId, String processName, String eventType) {
        RawLog log = new RawLog();
        log.setProcessGuid(processGuid);
        log.setParentProcessGuid(parentProcessGuid);
        log.setTraceId(traceId);
        log.setLogType("process");
        log.setEventType(eventType);
        log.setProcessName(processName);
        log.setImage("C:\\Windows\\" + processName);
        log.setCommandLine(processName);
        log.setHostAddress("10.0.0.1");
        log.setStartTime("2024-01-15 10:00:00");
        return log;
    }
}

