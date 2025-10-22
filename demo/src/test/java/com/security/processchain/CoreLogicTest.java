package com.security.processchain;

import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.*;
import org.junit.Test;

import java.util.*;

import static org.junit.Assert.*;

/**
 * 进程链核心逻辑测试
 * 
 * 测试范围：从获取到 RawAlarm 和 RawLog 数据后的所有逻辑
 * 1. ProcessChainBuilder.buildIncidentChain - 进程链构建
 * 2. 根节点识别逻辑
 * 3. Explore 节点创建逻辑  
 * 4. 断链检测和处理
 * 5. 多 traceId 支持
 * 6. 网端关联节点处理
 * 7. 节点裁剪逻辑
 */
public class CoreLogicTest {

    /**
     * 测试1：单个 traceId，有真实根节点
     */
    @Test
    public void test01_SingleTraceId_WithRootNode() {
        System.out.println("\n========== 测试1：单个traceId有真实根节点 ==========");
        
        // 模拟从 ES 查询到的数据
        String traceId = "TRACE_001";
        
        // 1个告警
        List<RawAlarm> alarms = Collections.singletonList(
            createAlarm("EVENT_001", traceId, traceId, null, "恶意进程告警", "高")
        );
        
        // 3条日志（根节点 + 2个子进程）
        List<RawLog> logs = Arrays.asList(
            createProcessLog(traceId, null, traceId, "malware.exe", "processCreate"),
            createProcessLog("CHILD_001", traceId, traceId, "cmd.exe", "processCreate"),
            createProcessLog("CHILD_002", "CHILD_001", traceId, "powershell.exe", "processCreate")
        );
        
        // 执行：构建进程链
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms,
            logs,
            Collections.singleton(traceId),
            new HashSet<>(),
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull("进程链不应为空", result);
        assertEquals("应该有3个节点", 3, result.getNodes().size());
        
        long rootCount = countRootNodes(result);
        assertEquals("应该有1个根节点", 1, rootCount);
        
        ProcessNode rootNode = getRootNode(result);
        assertEquals("根节点应该是traceId", traceId, rootNode.getNodeId());
        assertNotEquals("不应该创建Explore", "EXPLORE_ROOT", rootNode.getNodeId());
        
        System.out.println("✅ 根节点=" + rootNode.getNodeId() + ", 节点数=" + result.getNodes().size());
    }
    
    /**
     * 测试2：单个 traceId，无真实根节点（需要创建 Explore）
     */
    @Test
    public void test02_SingleTraceId_NoRootNode_CreateExplore() {
        System.out.println("\n========== 测试2：无真实根节点创建Explore ==========");
        
        // 模拟从 ES 查询到的数据（没有根节点）
        String traceId = "TRACE_001";
        
        List<RawAlarm> alarms = Collections.singletonList(
            createAlarm("EVENT_001", traceId, "NODE_MIDDLE", "NODE_PARENT", "告警", "高")
        );
        
        // 只有中间节点，没有根节点
        List<RawLog> logs = Arrays.asList(
            createProcessLog("NODE_MIDDLE", "NODE_PARENT", traceId, "cmd.exe", "processCreate"),
            createProcessLog("NODE_CHILD", "NODE_MIDDLE", traceId, "powershell.exe", "processCreate")
        );
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms,
            logs,
            Collections.singleton(traceId),
            new HashSet<>(),
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证：应该创建 Explore 虚拟根节点
        assertNotNull(result);
        
        long rootCount = countRootNodes(result);
        assertEquals("应该有1个根节点（Explore）", 1, rootCount);
        
        ProcessNode rootNode = getRootNode(result);
        assertEquals("应该创建EXPLORE_ROOT", "EXPLORE_ROOT", rootNode.getNodeId());
        assertTrue("Explore应该标记为根节点", rootNode.getChainNode().getIsRoot());
        
        long brokenCount = countBrokenNodes(result);
        assertTrue("应该有断链节点", brokenCount > 0);
        
        System.out.println("✅ Explore已创建, 断链数=" + brokenCount);
    }

    /**
     * 测试3：多个 traceId，每个都有根节点
     */
    @Test
    public void test03_MultipleTraceIds_AllWithRootNodes() {
        System.out.println("\n========== 测试3：多个traceId都有根节点 ==========");
        
        // 模拟从 ES 查询到的数据（3个 IP 的数据）
        List<RawAlarm> alarms = Arrays.asList(
            createAlarm("E001", "T001", "T001", null, "IP1告警", "高"),
            createAlarm("E002", "T002", "T002", null, "IP2告警", "中"),
            createAlarm("E003", "T003", "T003", null, "IP3告警", "高")
        );
        
        List<RawLog> logs = Arrays.asList(
            // IP1 的日志
            createProcessLog("T001", null, "T001", "process1.exe", "processCreate"),
            createProcessLog("T001_C1", "T001", "T001", "child1.exe", "processCreate"),
            
            // IP2 的日志
            createProcessLog("T002", null, "T002", "process2.exe", "processCreate"),
            createProcessLog("T002_C1", "T002", "T002", "child2.exe", "processCreate"),
            
            // IP3 的日志
            createProcessLog("T003", null, "T003", "process3.exe", "processCreate"),
            createProcessLog("T003_C1", "T003", "T003", "child3.exe", "processCreate")
        );
        
        Set<String> traceIds = new HashSet<>(Arrays.asList("T001", "T002", "T003"));
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms, logs, traceIds, new HashSet<>(),
            IncidentConverters.NODE_MAPPER, IncidentConverters.EDGE_MAPPER
        );
        
        // 验证：应该有3个根节点
        assertNotNull(result);
        assertEquals("应该有3个根节点", 3, countRootNodes(result));
        
        List<String> rootIds = getRootNodeIds(result);
        assertTrue("应该包含T001", rootIds.contains("T001"));
        assertTrue("应该包含T002", rootIds.contains("T002"));
        assertTrue("应该包含T003", rootIds.contains("T003"));
        assertFalse("不应该有Explore", rootIds.contains("EXPLORE_ROOT"));
        
        System.out.println("✅ 根节点=" + rootIds);
    }
    
    /**
     * 测试4：多个断链，统一连接到一个 Explore
     */
    @Test
    public void test04_MultipleBrokenChains_SingleExplore() {
        System.out.println("\n========== 测试4：多个断链统一Explore ==========");
        
        // 模拟从 ES 查询到的数据（3个独立的断链分支）
        String traceId = "TRACE_001";
        
        List<RawAlarm> alarms = Arrays.asList(
            createAlarm("E001", traceId, "BRANCH_A", "PARENT_A", "告警A", "高"),
            createAlarm("E002", traceId, "BRANCH_B", "PARENT_B", "告警B", "中"),
            createAlarm("E003", traceId, "BRANCH_C", "PARENT_C", "告警C", "高")
        );
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog("BRANCH_A", "PARENT_A", traceId, "processA.exe", "processCreate"),
            createProcessLog("BRANCH_A_C1", "BRANCH_A", traceId, "childA.exe", "processCreate"),
            createProcessLog("BRANCH_B", "PARENT_B", traceId, "processB.exe", "processCreate"),
            createProcessLog("BRANCH_C", "PARENT_C", traceId, "processC.exe", "processCreate")
        );
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms, logs, Collections.singleton(traceId), new HashSet<>(),
            IncidentConverters.NODE_MAPPER, IncidentConverters.EDGE_MAPPER
        );
        
        // 验证：只有1个 Explore 根节点
        assertNotNull(result);
        assertEquals("应该有且只有1个根节点", 1, countRootNodes(result));
        
        ProcessNode rootNode = getRootNode(result);
        assertEquals("应该是EXPLORE_ROOT", "EXPLORE_ROOT", rootNode.getNodeId());
        
        // 验证 Explore 连接到所有断链
        long exploreEdges = result.getEdges().stream()
            .filter(edge -> "EXPLORE_ROOT".equals(edge.getSource()))
            .count();
        assertTrue("Explore应该连接至少3个断链", exploreEdges >= 3);
        
        System.out.println("✅ Explore连接了" + exploreEdges + "个断链");
    }
    
    /**
     * 测试5：网端关联节点处理
     */
    @Test
    public void test05_AssociatedEventId_Marking() {
        System.out.println("\n========== 测试5：网端关联节点标记 ==========");
        
        // 模拟从 ES 查询到的数据
        String traceId = "TRACE_001";
        String associatedEventId = "ASSOC_EVENT_001";  // 网端关联的告警ID
        
        List<RawAlarm> alarms = Arrays.asList(
            createAlarm("E001", traceId, traceId, null, "根节点告警", "中"),
            createAlarm(associatedEventId, traceId, "ASSOC_NODE", traceId, "关联告警", "高")  // 关联告警
        );
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog(traceId, null, traceId, "root.exe", "processCreate"),
            createProcessLog("ASSOC_NODE", traceId, traceId, "associated.exe", "processCreate")
        );
        
        // 执行：传入 associatedEventIds
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms,
            logs,
            Collections.singleton(traceId),
            Collections.singleton(associatedEventId),  // ✅ 传入关联ID
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证：关联节点存在且标记正确
        assertNotNull(result);
        
        ProcessNode assocNode = result.getNodes().stream()
            .filter(node -> "ASSOC_NODE".equals(node.getNodeId()))
            .findFirst()
            .orElse(null);
        
        assertNotNull("应该找到关联节点", assocNode);
        assertTrue("关联节点应该是告警节点", assocNode.getChainNode().getIsAlarm());
        
        System.out.println("✅ 关联节点已正确标记");
    }
    
    /**
     * 测试6：节点裁剪逻辑（根节点保护）
     */
    @Test
    public void test06_NodePruning_RootNodeProtection() {
        System.out.println("\n========== 测试6：节点裁剪保护根节点 ==========");
        
        // 模拟从 ES 查询到的数据（超过限制的节点数）
        String traceId = "TRACE_001";
        
        List<RawAlarm> alarms = new ArrayList<>();
        alarms.add(createAlarm("E001", traceId, traceId, null, "根节点告警", "高"));
        
        List<RawLog> logs = new ArrayList<>();
        logs.add(createProcessLog(traceId, null, traceId, "root.exe", "processCreate"));
        
        // 创建长链（50个节点）
        String parentGuid = traceId;
        for (int i = 1; i <= 50; i++) {
            String childGuid = "NODE_" + String.format("%03d", i);
            logs.add(createProcessLog(childGuid, parentGuid, traceId, "process" + i + ".exe", "processCreate"));
            
            // 在第25个节点添加告警（确保被保留）
            if (i == 25) {
                alarms.add(createAlarm("E_MID", traceId, childGuid, parentGuid, "中间告警", "高"));
            }
            
            parentGuid = childGuid;
        }
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms, logs, Collections.singleton(traceId), new HashSet<>(),
            IncidentConverters.NODE_MAPPER, IncidentConverters.EDGE_MAPPER
        );
        
        // 验证：即使裁剪，根节点也必须保留
        assertNotNull(result);
        
        ProcessNode rootNode = result.getNodes().stream()
            .filter(node -> traceId.equals(node.getNodeId()))
            .findFirst()
            .orElse(null);
        
        assertNotNull("根节点必须被保留", rootNode);
        assertTrue("根节点应该标记为root", rootNode.getChainNode().getIsRoot());
        
        assertEquals("应该只有1个根节点", 1, countRootNodes(result));
        
        System.out.println("✅ 根节点已保护, 最终节点数=" + result.getNodes().size());
    }
    
    /**
     * 测试7：告警选举逻辑（同一个 traceId 的多个告警）
     */
    @Test
    public void test07_AlarmElection_SameTraceId() {
        System.out.println("\n========== 测试7：同traceId多个告警 ==========");
        
        // 模拟从 ES 查询到的数据（同一个 traceId 的多个告警）
        String traceId = "TRACE_001";
        
        List<RawAlarm> alarms = Arrays.asList(
            createAlarm("E001", traceId, traceId, null, "告警1", "高"),
            createAlarm("E002", traceId, "NODE_001", traceId, "告警2", "高"),
            createAlarm("E003", traceId, "NODE_002", "NODE_001", "告警3", "中")
        );
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog(traceId, null, traceId, "root.exe", "processCreate"),
            createProcessLog("NODE_001", traceId, traceId, "child1.exe", "processCreate"),
            createProcessLog("NODE_002", "NODE_001", traceId, "child2.exe", "processCreate")
        );
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms, logs, Collections.singleton(traceId), new HashSet<>(),
            IncidentConverters.NODE_MAPPER, IncidentConverters.EDGE_MAPPER
        );
        
        // 验证：所有告警节点都应该被标记
        assertNotNull(result);
        
        long alarmNodeCount = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() &&
                           node.getChainNode() != null &&
                           Boolean.TRUE.equals(node.getChainNode().getIsAlarm()))
            .count();
        
        assertEquals("应该有3个告警节点", 3, alarmNodeCount);
        
        System.out.println("✅ 告警节点数=" + alarmNodeCount);
    }
    
    /**
     * 测试8：边界情况 - 空数据
     */
    @Test
    public void test08_EdgeCase_EmptyData() {
        System.out.println("\n========== 测试8：边界情况-空数据 ==========");
        
        // 空数据
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            new ArrayList<>(),  // 空告警
            new ArrayList<>(),  // 空日志
            new HashSet<>(),
            new HashSet<>(),
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证：应该返回空的进程链
        assertNotNull(result);
        assertTrue("节点列表应该为空", result.getNodes() == null || result.getNodes().isEmpty());
        
        System.out.println("✅ 空数据处理正常");
    }
    
    // ==================== 辅助方法 ====================
    
    private long countRootNodes(IncidentProcessChain chain) {
        return chain.getNodes().stream()
            .filter(node -> node.getIsChainNode() &&
                           node.getChainNode() != null &&
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .count();
    }
    
    private ProcessNode getRootNode(IncidentProcessChain chain) {
        return chain.getNodes().stream()
            .filter(node -> node.getIsChainNode() &&
                           node.getChainNode() != null &&
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .findFirst()
            .orElse(null);
    }
    
    private List<String> getRootNodeIds(IncidentProcessChain chain) {
        return chain.getNodes().stream()
            .filter(node -> node.getIsChainNode() &&
                           node.getChainNode() != null &&
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .map(ProcessNode::getNodeId)
            .collect(java.util.stream.Collectors.toList());
    }
    
    private long countBrokenNodes(IncidentProcessChain chain) {
        return chain.getNodes().stream()
            .filter(node -> node.getIsChainNode() &&
                           node.getChainNode() != null &&
                           Boolean.TRUE.equals(node.getChainNode().getIsBroken()))
            .count();
    }
    
    private RawAlarm createAlarm(String eventId, String traceId, String processGuid,
                                  String parentProcessGuid, String alarmName, String severity) {
        RawAlarm alarm = new RawAlarm();
        alarm.setEventId(eventId);
        alarm.setTraceId(traceId);
        alarm.setProcessGuid(processGuid);
        alarm.setParentProcessGuid(parentProcessGuid);
        alarm.setAlarmName(alarmName);
        alarm.setThreatSeverity(severity);
        alarm.setHostAddress("192.168.1.100");
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
        log.setCommandLine(processName + " --args");
        log.setHostAddress("192.168.1.100");
        log.setStartTime("2024-01-15 10:00:00");
        return log;
    }
}

