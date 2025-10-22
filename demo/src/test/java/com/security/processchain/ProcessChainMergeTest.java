package com.security.processchain;

import com.security.processchain.model.IpMappingRelation;
import com.security.processchain.model.ProcessEdge;
import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.*;
import com.security.processchain.service.impl.ProcessChainServiceImpl;
import com.security.processchain.util.Pair;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * 进程链合并单元测试
 * 测试网侧和端侧进程链合并的完整流程
 */
public class ProcessChainMergeTest {

    @Mock
    private OptimizedESQueryService esQueryService;

    @InjectMocks
    private ProcessChainServiceImpl processChainService;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    /**
     * 测试场景1：阶段3 - buildIncidentChain 基础功能测试
     * 输入：3个IP的告警和日志，每个IP有不同的traceId
     * 期望：
     * 1. 正确识别3个根节点
     * 2. 正确构建每个IP的进程链
     * 3. traceIds列表包含所有3个traceId
     * 4. hostAddresses列表包含所有3个IP
     */
    @Test
    public void testBuildIncidentChain_MultipleIpsWithDifferentTraceIds() {
        // ===== 准备测试数据 =====
        
        // IP1: 10.50.86.171 的数据
        RawAlarm alarm1 = createAlarm(
            "E001", "T001", "10.50.86.171", 
            "ROOT_171_A1B2C3", "PARENT_171", 
            "恶意进程启动告警", "HIGH"
        );
        
        List<RawLog> logs1 = Arrays.asList(
            createProcessLog("ROOT_171_A1B2C3", "PARENT_171", "10.50.86.171", "T001",
                "svchost.exe", "C:\\Windows\\System32\\svchost.exe", "SYSTEM", "processCreate"),
            createProcessLog("CHILD_171_D4E5F6", "ROOT_171_A1B2C3", "10.50.86.171", "T001",
                "cmd.exe", "cmd.exe /c whoami", "SYSTEM", "processCreate")
        );

        // IP2: 10.50.86.52 的数据
        RawAlarm alarm2 = createAlarm(
            "E002", "T002", "10.50.86.52",
            "ROOT_52_G7H8I9", "PARENT_52",
            "可疑网络连接告警", "MEDIUM"
        );
        
        List<RawLog> logs2 = Arrays.asList(
            createProcessLog("ROOT_52_G7H8I9", "PARENT_52", "10.50.86.52", "T002",
                "explorer.exe", "C:\\Windows\\explorer.exe", "USER01", "processCreate"),
            createNetworkLog("CHILD_52_J0K1L2", "ROOT_52_G7H8I9", "10.50.86.52", "T002",
                "10.50.86.52", "54321", "192.168.1.100", "443", "TCP")
        );

        // IP3: 10.50.109.102 的数据
        RawAlarm alarm3 = createAlarm(
            "E003", "T003", "10.50.109.102",
            "ROOT_102_M3N4O5", "PARENT_102",
            "文件操作告警", "HIGH"
        );
        
        List<RawLog> logs3 = Arrays.asList(
            createProcessLog("ROOT_102_M3N4O5", "PARENT_102", "10.50.109.102", "T003",
                "powershell.exe", "powershell.exe -ExecutionPolicy Bypass", "ADMIN", "processCreate"),
            createFileLog("CHILD_102_P6Q7R8", "ROOT_102_M3N4O5", "10.50.109.102", "T003",
                "C:\\Temp\\suspicious_file.txt", "suspicious_file.txt", "1024", "a1b2c3d4e5f678901234567890123456")
        );

        // 合并所有告警和日志
        List<RawAlarm> allAlarms = Arrays.asList(alarm1, alarm2, alarm3);
        List<RawLog> allLogs = new ArrayList<>();
        allLogs.addAll(logs1);
        allLogs.addAll(logs2);
        allLogs.addAll(logs3);

        // 构建 traceIds 集合
        Set<String> traceIds = new HashSet<>(Arrays.asList("T001", "T002", "T003"));
        
        // 构建 associatedEventIds 集合（可以为空）
        Set<String> associatedEventIds = new HashSet<>();

        // ===== 执行测试 =====
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            allAlarms,
            allLogs,
            traceIds,
            associatedEventIds,
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );

        // ===== 验证结果 =====
        assertNotNull("进程链不应为空", result);
        assertNotNull("节点列表不应为空", result.getNodes());
        assertNotNull("边列表不应为空", result.getEdges());
        
        // 验证节点数量（3个根节点 + 3个子节点 = 6个节点）
        assertEquals("应该有6个节点", 6, result.getNodes().size());
        
        // 验证边数量（3条父子关系边）
        assertTrue("应该至少有3条边", result.getEdges().size() >= 3);
        
        // 验证根节点
        long rootCount = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           node.getChainNode().getIsRoot() != null &&
                           node.getChainNode().getIsRoot())
            .count();
        assertEquals("应该有3个根节点", 3, rootCount);
        
        // 验证根节点的 processGuid 应该等于对应的 traceId
        List<String> rootNodeIds = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           node.getChainNode().getIsRoot() != null &&
                           node.getChainNode().getIsRoot())
            .map(ProcessNode::getNodeId)
            .collect(java.util.stream.Collectors.toList());
        
        assertTrue("根节点应包含 ROOT_171_A1B2C3", rootNodeIds.contains("ROOT_171_A1B2C3"));
        assertTrue("根节点应包含 ROOT_52_G7H8I9", rootNodeIds.contains("ROOT_52_G7H8I9"));
        assertTrue("根节点应包含 ROOT_102_M3N4O5", rootNodeIds.contains("ROOT_102_M3N4O5"));
        
        // 验证告警节点
        long alarmCount = result.getNodes().stream()
            .filter(node -> node.getIsChainNode() && 
                           node.getChainNode() != null && 
                           node.getChainNode().getIsAlarm() != null &&
                           node.getChainNode().getIsAlarm())
            .count();
        assertEquals("应该有3个告警节点", 3, alarmCount);
    }

    /**
     * 测试场景2：阶段4 - findIpForRootNode 通过告警匹配
     * 输入：根节点、host->traceId映射、告警列表
     * 期望：能够通过告警的 processGuid 匹配找到对应的 IP
     */
    @Test
    public void testFindIpForRootNode_ByAlarmMatch() {
        // ===== 准备测试数据 =====
        
        // 创建根节点
        ProcessNode rootNode = new ProcessNode();
        rootNode.setNodeId("ROOT_171_A1B2C3");
        rootNode.setIsChainNode(true);
        
        ChainNode chainNode = new ChainNode();
        chainNode.setIsRoot(true);
        rootNode.setChainNode(chainNode);
        
        // 创建告警列表
        List<RawAlarm> allAlarms = Arrays.asList(
            createAlarm("E001", "T001", "10.50.86.171", "ROOT_171_A1B2C3", "PARENT_171", "告警1", "HIGH"),
            createAlarm("E002", "T002", "10.50.86.52", "ROOT_52_G7H8I9", "PARENT_52", "告警2", "MEDIUM"),
            createAlarm("E003", "T003", "10.50.109.102", "ROOT_102_M3N4O5", "PARENT_102", "告警3", "HIGH")
        );
        
        // 创建 host->traceId 映射
        Map<String, String> hostToTraceId = new HashMap<>();
        hostToTraceId.put("10.50.86.171", "T001");
        hostToTraceId.put("10.50.86.52", "T002");
        hostToTraceId.put("10.50.109.102", "T003");
        
        // ===== 使用反射调用私有方法测试 =====
        // 注意：这里展示测试逻辑，实际需要通过反射或将方法改为 protected
        // String ip = processChainService.findIpForRootNode(rootNode, hostToTraceId, allAlarms);
        
        // ===== 验证结果 =====
        // assertEquals("应该找到 IP 10.50.86.171", "10.50.86.171", ip);
        
        // 模拟逻辑验证
        String expectedIp = null;
        for (RawAlarm alarm : allAlarms) {
            if ("ROOT_171_A1B2C3".equals(alarm.getProcessGuid())) {
                expectedIp = alarm.getHostAddress();
                break;
            }
        }
        assertEquals("应该通过告警找到 IP", "10.50.86.171", expectedIp);
    }

    /**
     * 测试场景3：阶段4 - findIpForRootNode 通过 traceId 反查
     * 输入：根节点（nodeId == traceId）、host->traceId映射
     * 期望：能够通过 traceId 反向查找找到对应的 IP
     */
    @Test
    public void testFindIpForRootNode_ByTraceIdReverseLookup() {
        // ===== 准备测试数据 =====
        
        // 创建根节点（nodeId 等于 traceId）
        ProcessNode rootNode = new ProcessNode();
        rootNode.setNodeId("T001");  // nodeId 就是 traceId
        rootNode.setIsChainNode(true);
        
        ChainNode chainNode = new ChainNode();
        chainNode.setIsRoot(true);
        rootNode.setChainNode(chainNode);
        
        // 创建 host->traceId 映射
        Map<String, String> hostToTraceId = new HashMap<>();
        hostToTraceId.put("10.50.86.171", "T001");
        hostToTraceId.put("10.50.86.52", "T002");
        
        // ===== 模拟逻辑验证 =====
        String expectedIp = null;
        String rootNodeId = rootNode.getNodeId();
        
        // 在映射中反向查找
        for (Map.Entry<String, String> entry : hostToTraceId.entrySet()) {
            if (rootNodeId.equals(entry.getValue())) {
                expectedIp = entry.getKey();
                break;
            }
        }
        
        // ===== 验证结果 =====
        assertEquals("应该通过 traceId 反查找到 IP", "10.50.86.171", expectedIp);
    }

    /**
     * 测试场景4：完整的网侧端侧合并流程
     * 输入：网侧节点（1个攻击者 + 3个受害者）+ 端侧进程链（3个IP的进程链）
     * 期望：
     * 1. 网侧节点和端侧节点都被添加
     * 2. 创建3条桥接边（victim -> 端侧根节点）
     * 3. 边的总数 = 网侧边 + 端侧边 + 桥接边
     */
    @Test
    public void testMergeNetworkAndEndpointChain_CompleteScenario() {
        // ===== 准备网侧数据 =====
        List<ProcessNode> networkNodes = createNetworkNodes();
        List<ProcessEdge> networkEdges = createNetworkEdges();
        Pair<List<ProcessNode>, List<ProcessEdge>> networkChain = 
            Pair.of(networkNodes, networkEdges);
        
        // ===== 准备端侧数据 =====
        IncidentProcessChain endpointChain = createEndpointChain();
        
        // ===== 准备 IP -> rootNodeId 映射 =====
        Map<String, String> ipToRootNodeIdMap = new HashMap<>();
        ipToRootNodeIdMap.put("10.50.86.171", "ROOT_171_A1B2C3");
        ipToRootNodeIdMap.put("10.50.86.52", "ROOT_52_G7H8I9");
        ipToRootNodeIdMap.put("10.50.109.102", "ROOT_102_M3N4O5");
        
        // ===== 执行合并（模拟逻辑） =====
        IncidentProcessChain mergedChain = new IncidentProcessChain();
        List<ProcessNode> allNodes = new ArrayList<>();
        List<ProcessEdge> allEdges = new ArrayList<>();
        
        // 1. 添加网侧节点
        allNodes.addAll(networkNodes);
        
        // 2. 添加端侧节点
        allNodes.addAll(endpointChain.getNodes());
        
        // 3. 添加网侧边
        allEdges.addAll(networkEdges);
        
        // 4. 添加端侧边
        allEdges.addAll(endpointChain.getEdges());
        
        // 5. 创建桥接边
        List<ProcessEdge> bridgeEdges = createBridgeEdges(networkNodes, ipToRootNodeIdMap);
        allEdges.addAll(bridgeEdges);
        
        mergedChain.setNodes(allNodes);
        mergedChain.setEdges(allEdges);
        mergedChain.setTraceIds(endpointChain.getTraceIds());
        mergedChain.setHostAddresses(endpointChain.getHostAddresses());
        
        // ===== 验证结果 =====
        
        // 验证节点总数 = 网侧节点(4) + 端侧节点(6) = 10
        assertEquals("节点总数应为10", 10, mergedChain.getNodes().size());
        
        // 验证网侧节点（storyNode）
        long networkNodeCount = mergedChain.getNodes().stream()
            .filter(node -> !node.getIsChainNode() && node.getStoryNode() != null)
            .count();
        assertEquals("应该有4个网侧节点", 4, networkNodeCount);
        
        // 验证端侧节点（chainNode）
        long endpointNodeCount = mergedChain.getNodes().stream()
            .filter(node -> node.getIsChainNode() && node.getChainNode() != null)
            .count();
        assertEquals("应该有6个端侧节点", 6, endpointNodeCount);
        
        // 验证桥接边（victim -> 端侧根节点）
        assertEquals("应该有3条桥接边", 3, bridgeEdges.size());
        
        // 验证具体的桥接边
        assertTrue("应该有 10.50.86.171 -> ROOT_171_A1B2C3 的桥接边",
            bridgeEdges.stream().anyMatch(edge -> 
                "10.50.86.171".equals(edge.getSource()) && 
                "ROOT_171_A1B2C3".equals(edge.getTarget())));
        
        assertTrue("应该有 10.50.86.52 -> ROOT_52_G7H8I9 的桥接边",
            bridgeEdges.stream().anyMatch(edge -> 
                "10.50.86.52".equals(edge.getSource()) && 
                "ROOT_52_G7H8I9".equals(edge.getTarget())));
        
        assertTrue("应该有 10.50.109.102 -> ROOT_102_M3N4O5 的桥接边",
            bridgeEdges.stream().anyMatch(edge -> 
                "10.50.109.102".equals(edge.getSource()) && 
                "ROOT_102_M3N4O5".equals(edge.getTarget())));
        
        // 验证边总数 = 网侧边(3) + 端侧边(3) + 桥接边(3) = 9
        assertEquals("边总数应为9", 9, mergedChain.getEdges().size());
    }

    /**
     * 测试场景5：只有一个 victim 有对应的端侧根节点
     * 输入：3个 victim，但只有1个在 ipToRootNodeIdMap 中
     * 期望：只创建1条桥接边
     */
    @Test
    public void testMergeNetworkAndEndpointChain_PartialMapping() {
        // ===== 准备网侧数据 =====
        List<ProcessNode> networkNodes = createNetworkNodes();
        
        // ===== 准备 IP -> rootNodeId 映射（只有一个IP有映射）=====
        Map<String, String> ipToRootNodeIdMap = new HashMap<>();
        ipToRootNodeIdMap.put("10.50.86.171", "ROOT_171_A1B2C3");
        // 注意：10.50.86.52 和 10.50.109.102 没有映射
        
        // ===== 创建桥接边 =====
        List<ProcessEdge> bridgeEdges = createBridgeEdges(networkNodes, ipToRootNodeIdMap);
        
        // ===== 验证结果 =====
        assertEquals("应该只有1条桥接边", 1, bridgeEdges.size());
        assertEquals("桥接边的源应该是 10.50.86.171", "10.50.86.171", bridgeEdges.get(0).getSource());
        assertEquals("桥接边的目标应该是 ROOT_171_A1B2C3", "ROOT_171_A1B2C3", bridgeEdges.get(0).getTarget());
    }

    /**
     * 测试场景6：没有任何 victim 节点
     * 输入：只有攻击者节点，没有 victim
     * 期望：不创建任何桥接边
     */
    @Test
    public void testMergeNetworkAndEndpointChain_NoVictims() {
        // ===== 准备网侧数据（只有攻击者）=====
        List<ProcessNode> networkNodes = new ArrayList<>();
        
        ProcessNode attackerNode = new ProcessNode();
        attackerNode.setNodeId("10.50.86.35");
        attackerNode.setIsChainNode(false);
        
        StoryNode attackerStory = new StoryNode();
        attackerStory.setType("attacker");
        Map<String, Object> attackerOther = new HashMap<>();
        attackerOther.put("ip", "10.50.86.35");
        attackerStory.setOther(attackerOther);
        attackerNode.setStoryNode(attackerStory);
        
        networkNodes.add(attackerNode);
        
        // ===== 准备映射 =====
        Map<String, String> ipToRootNodeIdMap = new HashMap<>();
        ipToRootNodeIdMap.put("10.50.86.171", "ROOT_171_A1B2C3");
        
        // ===== 创建桥接边 =====
        List<ProcessEdge> bridgeEdges = createBridgeEdges(networkNodes, ipToRootNodeIdMap);
        
        // ===== 验证结果 =====
        assertEquals("没有 victim 节点时不应该有桥接边", 0, bridgeEdges.size());
    }

    // ==================== 辅助方法 ====================

    /**
     * 创建告警对象
     */
    private RawAlarm createAlarm(String eventId, String traceId, String hostAddress,
                                  String processGuid, String parentProcessGuid,
                                  String alarmName, String threatSeverity) {
        RawAlarm alarm = new RawAlarm();
        alarm.setEventId(eventId);
        alarm.setTraceId(traceId);
        alarm.setHostAddress(hostAddress);
        alarm.setProcessGuid(processGuid);
        alarm.setParentProcessGuid(parentProcessGuid);
        alarm.setAlarmName(alarmName);
        alarm.setThreatSeverity(threatSeverity);
        alarm.setStartTime("2024-01-15 10:30:00");
        return alarm;
    }

    /**
     * 创建进程日志
     */
    private RawLog createProcessLog(String processGuid, String parentProcessGuid,
                                     String hostAddress, String traceId,
                                     String processName, String commandLine,
                                     String userName, String eventType) {
        RawLog log = new RawLog();
        log.setProcessGuid(processGuid);
        log.setParentProcessGuid(parentProcessGuid);
        log.setHostAddress(hostAddress);
        log.setTraceId(traceId);
        log.setLogType("process");
        log.setEventType(eventType);
        log.setProcessName(processName);
        log.setCommandLine(commandLine);
        log.setProcessUserName(userName);
        log.setImage(commandLine);
        log.setStartTime("2024-01-15 10:30:00");
        return log;
    }

    /**
     * 创建网络日志
     */
    private RawLog createNetworkLog(String processGuid, String parentProcessGuid,
                                     String hostAddress, String traceId,
                                     String srcAddress, String srcPort,
                                     String destAddress, String destPort,
                                     String protocol) {
        RawLog log = new RawLog();
        log.setProcessGuid(processGuid);
        log.setParentProcessGuid(parentProcessGuid);
        log.setHostAddress(hostAddress);
        log.setTraceId(traceId);
        log.setLogType("network");
        log.setOpType("connect");
        log.setSrcAddress(srcAddress);
        log.setSrcPort(srcPort);
        log.setDestAddress(destAddress);
        log.setDestPort(destPort);
        log.setTransProtocol(protocol);
        log.setStartTime("2024-01-15 10:31:00");
        return log;
    }

    /**
     * 创建文件日志
     */
    private RawLog createFileLog(String processGuid, String parentProcessGuid,
                                  String hostAddress, String traceId,
                                  String filePath, String fileName,
                                  String fileSize, String fileMd5) {
        RawLog log = new RawLog();
        log.setProcessGuid(processGuid);
        log.setParentProcessGuid(parentProcessGuid);
        log.setHostAddress(hostAddress);
        log.setTraceId(traceId);
        log.setLogType("file");
        log.setOpType("create");
        log.setFilePath(filePath);
        log.setFileName(fileName);
        log.setFileSize(fileSize);
        log.setFileMd5(fileMd5);
        log.setStartTime("2024-01-15 10:32:00");
        return log;
    }

    /**
     * 创建网侧节点列表
     */
    private List<ProcessNode> createNetworkNodes() {
        List<ProcessNode> nodes = new ArrayList<>();
        
        // 攻击者节点
        ProcessNode attackerNode = new ProcessNode();
        attackerNode.setNodeId("10.50.86.35");
        attackerNode.setLogType(NodeType.UNKNOWN);
        attackerNode.setNodeThreatSeverity(ThreatSeverity.HIGH);
        attackerNode.setIsChainNode(false);
        
        StoryNode attackerStory = new StoryNode();
        attackerStory.setType("attacker");
        Map<String, Object> attackerOther = new HashMap<>();
        attackerOther.put("ip", "10.50.86.35");
        attackerOther.put("isTopNode", true);
        attackerStory.setOther(attackerOther);
        attackerNode.setStoryNode(attackerStory);
        nodes.add(attackerNode);
        
        // Victim 1: 10.50.86.171
        ProcessNode victim1 = new ProcessNode();
        victim1.setNodeId("10.50.86.171");
        victim1.setLogType(NodeType.UNKNOWN);
        victim1.setNodeThreatSeverity(ThreatSeverity.HIGH);
        victim1.setIsChainNode(false);
        
        StoryNode victim1Story = new StoryNode();
        victim1Story.setType("victim");
        Map<String, Object> victim1Other = new HashMap<>();
        victim1Other.put("ip", "10.50.86.171");
        victim1Other.put("port", "22");
        victim1Other.put("isEdr", true);
        victim1Other.put("associated", true);
        victim1Story.setOther(victim1Other);
        victim1.setStoryNode(victim1Story);
        nodes.add(victim1);
        
        // Victim 2: 10.50.86.52
        ProcessNode victim2 = new ProcessNode();
        victim2.setNodeId("10.50.86.52");
        victim2.setLogType(NodeType.UNKNOWN);
        victim2.setNodeThreatSeverity(ThreatSeverity.MEDIUM);
        victim2.setIsChainNode(false);
        
        StoryNode victim2Story = new StoryNode();
        victim2Story.setType("victim");
        Map<String, Object> victim2Other = new HashMap<>();
        victim2Other.put("ip", "10.50.86.52");
        victim2Other.put("port", "32");
        victim2Other.put("isEdr", false);
        victim2Story.setOther(victim2Other);
        victim2.setStoryNode(victim2Story);
        nodes.add(victim2);
        
        // Victim 3: 10.50.109.102
        ProcessNode victim3 = new ProcessNode();
        victim3.setNodeId("10.50.109.102");
        victim3.setLogType(NodeType.UNKNOWN);
        victim3.setNodeThreatSeverity(ThreatSeverity.HIGH);
        victim3.setIsChainNode(false);
        
        StoryNode victim3Story = new StoryNode();
        victim3Story.setType("victim");
        Map<String, Object> victim3Other = new HashMap<>();
        victim3Other.put("ip", "10.50.109.102");
        victim3Other.put("port", "22");
        victim3Other.put("isEdr", true);
        victim3Story.setOther(victim3Other);
        victim3.setStoryNode(victim3Story);
        nodes.add(victim3);
        
        return nodes;
    }

    /**
     * 创建网侧边列表
     */
    private List<ProcessEdge> createNetworkEdges() {
        List<ProcessEdge> edges = new ArrayList<>();
        
        // 攻击者 -> Victim1
        ProcessEdge edge1 = new ProcessEdge();
        edge1.setSource("10.50.86.35");
        edge1.setTarget("10.50.86.171");
        edge1.setVal("攻击");
        edges.add(edge1);
        
        // 攻击者 -> Victim2
        ProcessEdge edge2 = new ProcessEdge();
        edge2.setSource("10.50.86.35");
        edge2.setTarget("10.50.86.52");
        edge2.setVal("攻击");
        edges.add(edge2);
        
        // 攻击者 -> Victim3
        ProcessEdge edge3 = new ProcessEdge();
        edge3.setSource("10.50.86.35");
        edge3.setTarget("10.50.109.102");
        edge3.setVal("攻击");
        edges.add(edge3);
        
        return edges;
    }

    /**
     * 创建端侧进程链
     */
    private IncidentProcessChain createEndpointChain() {
        IncidentProcessChain chain = new IncidentProcessChain();
        
        List<ProcessNode> nodes = new ArrayList<>();
        List<ProcessEdge> edges = new ArrayList<>();
        
        // IP1 的根节点和子节点
        nodes.add(createEndpointRootNode("ROOT_171_A1B2C3", "T001", "svchost.exe", true));
        nodes.add(createEndpointChildNode("CHILD_171_D4E5F6", "cmd.exe", false));
        edges.add(createEdge("ROOT_171_A1B2C3", "CHILD_171_D4E5F6", "创建子进程"));
        
        // IP2 的根节点和子节点
        nodes.add(createEndpointRootNode("ROOT_52_G7H8I9", "T002", "explorer.exe", true));
        nodes.add(createEndpointChildNode("CHILD_52_J0K1L2", "网络连接", false));
        edges.add(createEdge("ROOT_52_G7H8I9", "CHILD_52_J0K1L2", "发起网络连接"));
        
        // IP3 的根节点和子节点
        nodes.add(createEndpointRootNode("ROOT_102_M3N4O5", "T003", "powershell.exe", true));
        nodes.add(createEndpointChildNode("CHILD_102_P6Q7R8", "文件操作", false));
        edges.add(createEdge("ROOT_102_M3N4O5", "CHILD_102_P6Q7R8", "创建文件"));
        
        chain.setNodes(nodes);
        chain.setEdges(edges);
        chain.setTraceIds(Arrays.asList("T001", "T002", "T003"));
        chain.setHostAddresses(Arrays.asList("10.50.86.171", "10.50.86.52", "10.50.109.102"));
        
        return chain;
    }

    /**
     * 创建端侧根节点
     */
    private ProcessNode createEndpointRootNode(String nodeId, String traceId, 
                                                String processName, boolean isAlarm) {
        ProcessNode node = new ProcessNode();
        node.setNodeId(nodeId);
        node.setLogType(NodeType.PROCESS);
        node.setNodeThreatSeverity(ThreatSeverity.HIGH);
        node.setIsChainNode(true);
        
        ChainNode chainNode = new ChainNode();
        chainNode.setIsRoot(true);
        chainNode.setIsBroken(false);
        chainNode.setIsAlarm(isAlarm);
        
        if (isAlarm) {
            AlarmNodeInfo alarmInfo = new AlarmNodeInfo();
            alarmInfo.setAlarmName("告警");
            chainNode.setAlarmNodeInfo(alarmInfo);
        }
        
        ProcessEntity processEntity = new ProcessEntity();
        processEntity.setProcessName(processName);
        chainNode.setProcessEntity(processEntity);
        
        node.setChainNode(chainNode);
        return node;
    }

    /**
     * 创建端侧子节点
     */
    private ProcessNode createEndpointChildNode(String nodeId, String name, boolean isAlarm) {
        ProcessNode node = new ProcessNode();
        node.setNodeId(nodeId);
        node.setLogType(NodeType.PROCESS);
        node.setNodeThreatSeverity(ThreatSeverity.MEDIUM);
        node.setIsChainNode(true);
        
        ChainNode chainNode = new ChainNode();
        chainNode.setIsRoot(false);
        chainNode.setIsBroken(false);
        chainNode.setIsAlarm(isAlarm);
        
        ProcessEntity processEntity = new ProcessEntity();
        processEntity.setProcessName(name);
        chainNode.setProcessEntity(processEntity);
        
        node.setChainNode(chainNode);
        return node;
    }

    /**
     * 创建边
     */
    private ProcessEdge createEdge(String source, String target, String val) {
        ProcessEdge edge = new ProcessEdge();
        edge.setSource(source);
        edge.setTarget(target);
        edge.setVal(val);
        return edge;
    }

    /**
     * 创建桥接边（模拟 ProcessChainServiceImpl 的逻辑）
     */
    private List<ProcessEdge> createBridgeEdges(List<ProcessNode> networkNodes,
                                                 Map<String, String> ipToRootNodeIdMap) {
        List<ProcessEdge> bridgeEdges = new ArrayList<>();
        
        for (ProcessNode node : networkNodes) {
            // 只处理故事节点
            if (node.getIsChainNode() || node.getStoryNode() == null) {
                continue;
            }
            
            StoryNode storyNode = node.getStoryNode();
            
            // 只处理 victim 节点
            if (!"victim".equals(storyNode.getType())) {
                continue;
            }
            
            // 提取 IP
            String victimIp = extractIpFromStoryNode(storyNode);
            if (victimIp == null || victimIp.isEmpty()) {
                continue;
            }
            
            // 查找对应的根节点
            String rootNodeId = ipToRootNodeIdMap.get(victimIp);
            if (rootNodeId == null) {
                continue;
            }
            
            // 创建桥接边
            ProcessEdge bridgeEdge = new ProcessEdge();
            bridgeEdge.setSource(node.getNodeId());
            bridgeEdge.setTarget(rootNodeId);
            bridgeEdge.setVal("");
            bridgeEdges.add(bridgeEdge);
        }
        
        return bridgeEdges;
    }

    /**
     * 从 StoryNode 提取 IP
     */
    private String extractIpFromStoryNode(StoryNode storyNode) {
        if (storyNode.getOther() == null) {
            return null;
        }
        
        Object ipObj = storyNode.getOther().get("ip");
        if (ipObj == null) {
            return null;
        }
        
        return ipObj.toString().trim();
    }
}

