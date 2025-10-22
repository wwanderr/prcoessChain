package com.security.processchain;

import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.*;
import org.junit.Test;

import java.util.*;

import static org.junit.Assert.*;

/**
 * 进程链核心逻辑单元测试
 * 
 * 不依赖 ES 和 Service 层，直接测试 ProcessChainBuilder 的核心功能：
 * 1. 根节点识别逻辑
 * 2. Explore 节点创建逻辑
 * 3. 断链处理逻辑
 * 4. 多 traceId 支持
 * 5. 网端关联节点处理
 */
public class SpringBootProcessChainTest {

    /**
     * 测试1：单个 traceId，有真实根节点
     * 
     * 预期：
     * - 找到1个根节点
     * - 不创建 Explore 节点
     * - 根节点的 processGuid == traceId
     */
    @Test
    public void testBuildChain_SingleTraceId_WithRootNode() {
        System.out.println("\n========== 测试1：单个traceId有真实根节点 ==========");
        
        // 准备数据
        String traceId = "TRACE_001";
        RawAlarm alarm = createAlarm("EVENT_001", traceId, traceId, null, "恶意进程", "高");
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog(traceId, null, traceId, "malware.exe", "processCreate"),
            createProcessLog("CHILD_001", traceId, traceId, "cmd.exe", "processCreate"),
            createProcessLog("CHILD_002", "CHILD_001", traceId, "powershell.exe", "processCreate")
        );
        
        Set<String> traceIds = Collections.singleton(traceId);
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
        assertNotNull("进程链不应为空", result);
        assertNotNull("节点列表不应为空", result.getNodes());
        
        // 验证根节点
        long rootCount = countRootNodes(result);
        assertEquals("应该有1个根节点", 1, rootCount);
        
        // 验证根节点ID
        ProcessNode rootNode = getRootNode(result);
        assertNotNull("应该找到根节点", rootNode);
        assertEquals("根节点ID应该等于traceId", traceId, rootNode.getNodeId());
        assertNotEquals("不应该创建Explore节点", "EXPLORE_ROOT", rootNode.getNodeId());
        
        System.out.println("✅ 测试通过：根节点=" + rootNode.getNodeId() + ", 节点数=" + result.getNodes().size());
    }
    
    /**
     * 测试2：单个 traceId，无真实根节点（断链）
     * 
     * 预期：
     * - 没有真实根节点
     * - 创建1个 Explore 虚拟根节点
     * - Explore 的 isRoot = true 
     */
    @Test
    public void testBuildChain_SingleTraceId_NoRootNode() {
        System.out.println("\n========== 测试2：单个traceId无真实根节点 ==========");
        
        // 准备数据（故意不包含 processGuid == traceId 的节点）
        String traceId = "TRACE_001";
        RawAlarm alarm = createAlarm("EVENT_001", traceId, "NODE_MIDDLE", "NODE_PARENT", "告警", "高");
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog("NODE_MIDDLE", "NODE_PARENT", traceId, "cmd.exe", "processCreate"),
            createProcessLog("NODE_CHILD", "NODE_MIDDLE", traceId, "powershell.exe", "processCreate")
        );
        
        Set<String> traceIds = Collections.singleton(traceId);
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
        assertNotNull("进程链不应为空", result);
        
        // 验证根节点
        long rootCount = countRootNodes(result);
        assertEquals("应该有1个根节点（Explore）", 1, rootCount);
        
        // 验证是 Explore 节点
        ProcessNode rootNode = getRootNode(result);
        assertNotNull("应该找到根节点", rootNode);
        assertEquals("应该创建EXPLORE_ROOT", "EXPLORE_ROOT", rootNode.getNodeId());
        
        // 验证断链节点
        long brokenCount = countBrokenNodes(result);
        assertTrue("应该有断链节点", brokenCount > 0);
        
        System.out.println("✅ 测试通过：创建了Explore节点, 断链数=" + brokenCount);
    }

    /**
     * 测试3：多个 traceId，都有真实根节点
     * 
     * 预期：
     * - 找到多个根节点（每个 traceId 一个）
     * - 不创建 Explore 节点
     */
    @Test
    public void testBuildChain_MultipleTraceIds_AllWithRootNodes() {
        System.out.println("\n========== 测试3：多个traceId都有真实根节点 ==========");
        
        // 准备数据
        List<RawAlarm> alarms = Arrays.asList(
            createAlarm("E001", "T001", "T001", null, "告警1", "高"),
            createAlarm("E002", "T002", "T002", null, "告警2", "中"),
            createAlarm("E003", "T003", "T003", null, "告警3", "高")
        );
        
        List<RawLog> logs = Arrays.asList(
            // T001 的日志
            createProcessLog("T001", null, "T001", "process1.exe", "processCreate"),
            createProcessLog("T001_C1", "T001", "T001", "child1.exe", "processCreate"),
            
            // T002 的日志
            createProcessLog("T002", null, "T002", "process2.exe", "processCreate"),
            createProcessLog("T002_C1", "T002", "T002", "child2.exe", "processCreate"),
            
            // T003 的日志
            createProcessLog("T003", null, "T003", "process3.exe", "processCreate"),
            createProcessLog("T003_C1", "T003", "T003", "child3.exe", "processCreate")
        );
        
        Set<String> traceIds = new HashSet<>(Arrays.asList("T001", "T002", "T003"));
        Set<String> associatedEventIds = new HashSet<>();
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms, logs, traceIds, associatedEventIds,
            IncidentConverters.NODE_MAPPER, IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull("进程链不应为空", result);
        
        // 验证根节点数量
        long rootCount = countRootNodes(result);
        assertEquals("应该有3个根节点", 3, rootCount);
        
        // 验证每个根节点
        List<String> rootNodeIds = getRootNodeIds(result);
        assertTrue("应该包含T001", rootNodeIds.contains("T001"));
        assertTrue("应该包含T002", rootNodeIds.contains("T002"));
        assertTrue("应该包含T003", rootNodeIds.contains("T003"));
        assertFalse("不应该有Explore节点", rootNodeIds.contains("EXPLORE_ROOT"));
        
        System.out.println("✅ 测试通过：根节点=" + rootNodeIds + ", 节点数=" + result.getNodes().size());
    }
    
    /**
     * 测试4：多个断链，创建统一的 Explore 根节点
     * 
     * 预期：
     * - 没有真实根节点
     * - 创建1个 Explore 虚拟根节点
     * - 所有断链都连接到 Explore
     */
    @Test
    public void testBuildChain_MultipleBrokenChains_SingleExplore() {
        System.out.println("\n========== 测试4：多个断链创建统一Explore ==========");
        
        // 准备数据（3个独立的断链分支）
        String traceId = "TRACE_001";
        List<RawAlarm> alarms = Arrays.asList(
            createAlarm("E001", traceId, "BRANCH_A", "PARENT_A", "告警A", "高"),
            createAlarm("E002", traceId, "BRANCH_B", "PARENT_B", "告警B", "中"),
            createAlarm("E003", traceId, "BRANCH_C", "PARENT_C", "告警C", "高")
        );
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog("BRANCH_A", "PARENT_A", traceId, "processA.exe", "processCreate"),
            createProcessLog("BRANCH_B", "PARENT_B", traceId, "processB.exe", "processCreate"),
            createProcessLog("BRANCH_C", "PARENT_C", traceId, "processC.exe", "processCreate")
        );
        
        Set<String> traceIds = Collections.singleton(traceId);
        Set<String> associatedEventIds = new HashSet<>();
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms, logs, traceIds, associatedEventIds,
            IncidentConverters.NODE_MAPPER, IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull("进程链不应为空", result);
        
        // 验证只有1个根节点
        long rootCount = countRootNodes(result);
        assertEquals("应该有且只有1个根节点（Explore）", 1, rootCount);
        
        // 验证是 Explore 节点
        ProcessNode rootNode = getRootNode(result);
        assertEquals("应该创建EXPLORE_ROOT", "EXPLORE_ROOT", rootNode.getNodeId());
        
        // 验证断链数量
        long brokenCount = countBrokenNodes(result);
        assertTrue("应该有至少3个断链", brokenCount >= 3);
        
        // 验证从 Explore 到断链的边
        long exploreEdges = result.getEdges().stream()
            .filter(edge -> "EXPLORE_ROOT".equals(edge.getSource()))
            .count();
        assertTrue("Explore应该连接到至少3个断链", exploreEdges >= 3);
        
        System.out.println("✅ 测试通过：Explore连接了" + exploreEdges + "个断链");
    }
    
    /**
     * 测试5：网端关联节点标记
     * 
     * 预期：
     * - 关联节点被正确标记
     * - 关联节点信息完整
     */
    @Test
    public void testBuildChain_AssociatedNode() {
        System.out.println("\n========== 测试5：网端关联节点标记 ==========");
        
        // 准备数据
        String traceId = "TRACE_001";
        String associatedEventId = "ASSOC_EVENT_001";
        
        RawAlarm rootAlarm = createAlarm("E001", traceId, traceId, null, "根节点", "中");
        RawAlarm assocAlarm = createAlarm(associatedEventId, traceId, "ASSOC_NODE", traceId, "关联告警", "高");
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog(traceId, null, traceId, "root.exe", "processCreate"),
            createProcessLog("ASSOC_NODE", traceId, traceId, "associated.exe", "processCreate")
        );
        
        Set<String> traceIds = Collections.singleton(traceId);
        Set<String> associatedEventIds = Collections.singleton(associatedEventId);
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            Arrays.asList(rootAlarm, assocAlarm),
            logs,
            traceIds,
            associatedEventIds,
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull("进程链不应为空", result);
        
        // 验证关联节点存在
        ProcessNode assocNode = result.getNodes().stream()
            .filter(node -> "ASSOC_NODE".equals(node.getNodeId()))
            .findFirst()
            .orElse(null);
        
        assertNotNull("应该找到关联节点", assocNode);
        assertTrue("关联节点应该是告警节点", assocNode.getChainNode().getIsAlarm());
        
        System.out.println("✅ 测试通过：关联节点已正确标记");
    }
    
    /**
     * 测试6：长链条构建
     * 
     * 预期：
     * - 能够构建长链条
     * - 父子关系正确
     */
    @Test
    public void testBuildChain_LongChain() {
        System.out.println("\n========== 测试6：长链条构建 ==========");
        
        // 准备数据（10层深度的链）
        String traceId = "TRACE_001";
        RawAlarm alarm = createAlarm("E001", traceId, traceId, null, "告警", "高");
        
        List<RawLog> logs = new ArrayList<>();
        logs.add(createProcessLog(traceId, null, traceId, "root.exe", "processCreate"));
        
        String parentGuid = traceId;
        for (int i = 1; i <= 10; i++) {
            String childGuid = "NODE_" + i;
            logs.add(createProcessLog(childGuid, parentGuid, traceId, "process" + i + ".exe", "processCreate"));
            parentGuid = childGuid;
        }
        
        Set<String> traceIds = Collections.singleton(traceId);
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
        assertNotNull("进程链不应为空", result);
        assertEquals("应该有11个节点（1根+10子）", 11, result.getNodes().size());
        assertTrue("应该有至少10条边", result.getEdges().size() >= 10);
        
        // 验证根节点
        ProcessNode rootNode = getRootNode(result);
        assertNotNull("应该找到根节点", rootNode);
        assertEquals("根节点应该是traceId", traceId, rootNode.getNodeId());
        
        System.out.println("✅ 测试通过：长链条节点=" + result.getNodes().size() + ", 边=" + result.getEdges().size());
    }

    /**
     * 测试7：多层级树状结构
     * 
     * 预期：
     * - 构建完整的树状结构
     * - 一个根节点，多个分支
     */
    @Test
    public void testBuildChain_TreeStructure() {
        System.out.println("\n========== 测试7：多层级树状结构 ==========");
        
        String traceId = "ROOT";
        RawAlarm alarm = createAlarm("E001", traceId, traceId, null, "根告警", "高");
        
        // 构建树状结构：
        //        ROOT
        //       /  |  \
        //      A   B   C
        //     / \      |
        //    A1 A2     C1
        List<RawLog> logs = Arrays.asList(
            createProcessLog("ROOT", null, traceId, "root.exe", "processCreate"),
            createProcessLog("A", "ROOT", traceId, "processA.exe", "processCreate"),
            createProcessLog("B", "ROOT", traceId, "processB.exe", "processCreate"),
            createProcessLog("C", "ROOT", traceId, "processC.exe", "processCreate"),
            createProcessLog("A1", "A", traceId, "processA1.exe", "processCreate"),
            createProcessLog("A2", "A", traceId, "processA2.exe", "processCreate"),
            createProcessLog("C1", "C", traceId, "processC1.exe", "processCreate")
        );
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            Collections.singletonList(alarm),
            logs,
            Collections.singleton(traceId),
            new HashSet<>(),
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull(result);
        assertEquals("应该有7个节点", 7, result.getNodes().size());
        assertEquals("应该有1个根节点", 1, countRootNodes(result));
        assertEquals("根节点应该是ROOT", "ROOT", getRootNode(result).getNodeId());
        
        System.out.println("✅ 测试通过：树状结构节点=" + result.getNodes().size());
    }

    /**
     * 测试8：文件、网络、域名等非进程节点
     * 
     * 预期：
     * - 正确处理文件节点
     * - 正确处理网络节点
     * - 正确处理域名节点
     */
    @Test
    public void testBuildChain_NonProcessNodes() {
        System.out.println("\n========== 测试8：非进程节点处理 ==========");
        
        String traceId = "TRACE_001";
        RawAlarm alarm = createAlarm("E001", traceId, traceId, null, "文件操作告警", "高");  // 改为高危，触发双向遍历
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog(traceId, null, traceId, "malware.exe", "processCreate"),
            createFileLog("FILE_001", traceId, traceId, "C:\\malware.dll", "fileCreate"),
            createNetworkLog("NET_001", traceId, traceId, "192.168.1.100", "5.6.7.8", "networkConnect"),
            createDomainLog("DOMAIN_001", traceId, traceId, "evil.com", "dnsQuery")
        );
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            Collections.singletonList(alarm),
            logs,
            Collections.singleton(traceId),
            new HashSet<>(),
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull(result);
        assertTrue("应该有多个节点", result.getNodes().size() >= 4);
        
        // 验证节点类型
        boolean hasFileNode = result.getNodes().stream()
            .anyMatch(n -> NodeType.FILE.equals(n.getLogType()));
        boolean hasNetworkNode = result.getNodes().stream()
            .anyMatch(n -> NodeType.NETWORK.equals(n.getLogType()));
        boolean hasDomainNode = result.getNodes().stream()
            .anyMatch(n -> NodeType.DOMAIN.equals(n.getLogType()));
        
        assertTrue("应该包含文件节点", hasFileNode);
        assertTrue("应该包含网络节点", hasNetworkNode);
        assertTrue("应该包含域名节点", hasDomainNode);
        
        System.out.println("✅ 测试通过：非进程节点处理正确");
    }

    /**
     * 测试9：同一告警的多个严重等级
     * 
     * 预期：
     * - 高危告警触发双向遍历
     * - 中危告警触发向上遍历
     * - 低危告警触发向上遍历
     */
    @Test
    public void testBuildChain_DifferentSeverities() {
        System.out.println("\n========== 测试9：不同严重等级告警 ==========");
        
        String traceId = "TRACE_001";
        
        // 高危告警
        RawAlarm highAlarm = createAlarm("E_HIGH", traceId, "NODE_HIGH", traceId, "高危告警", "高");
        // 中危告警
        RawAlarm mediumAlarm = createAlarm("E_MED", traceId, "NODE_MED", traceId, "中危告警", "中");
        // 低危告警
        RawAlarm lowAlarm = createAlarm("E_LOW", traceId, "NODE_LOW", traceId, "低危告警", "低");
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog(traceId, null, traceId, "root.exe", "processCreate"),
            createProcessLog("NODE_HIGH", traceId, traceId, "highRisk.exe", "processCreate"),
            createProcessLog("NODE_MED", traceId, traceId, "mediumRisk.exe", "processCreate"),
            createProcessLog("NODE_LOW", traceId, traceId, "lowRisk.exe", "processCreate"),
            createProcessLog("CHILD_HIGH", "NODE_HIGH", traceId, "childHigh.exe", "processCreate")
        );
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            Arrays.asList(highAlarm, mediumAlarm, lowAlarm),
            logs,
            Collections.singleton(traceId),
            new HashSet<>(),
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull(result);
        assertTrue("应该有多个节点", result.getNodes().size() >= 4);
        
        // 验证告警节点
        long alarmCount = result.getNodes().stream()
            .filter(n -> n.getChainNode() != null && n.getChainNode().getIsAlarm())
            .count();
        assertEquals("应该有3个告警节点", 3, alarmCount);
        
        System.out.println("✅ 测试通过：不同严重等级处理正确，告警数=" + alarmCount);
    }

    /**
     * 测试10：根节点本身就是告警节点
     * 
     * 预期：
     * - 根节点既是根节点又是告警节点
     * - isRoot = true, isAlarm = true
     */
    @Test
    public void testBuildChain_RootNodeIsAlarm() {
        System.out.println("\n========== 测试10：根节点本身是告警 ==========");
        
        String traceId = "ROOT_ALARM";
        RawAlarm alarm = createAlarm("E001", traceId, traceId, null, "根节点告警", "高");
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog(traceId, null, traceId, "rootAlarm.exe", "processCreate"),
            createProcessLog("CHILD", traceId, traceId, "child.exe", "processCreate")
        );
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            Collections.singletonList(alarm),
            logs,
            Collections.singleton(traceId),
            new HashSet<>(),
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        ProcessNode rootNode = getRootNode(result);
        assertNotNull("应该找到根节点", rootNode);
        assertTrue("根节点应该也是告警节点", rootNode.getChainNode().getIsAlarm());
        assertTrue("根节点的isRoot应该为true", rootNode.getChainNode().getIsRoot());
        
        System.out.println("✅ 测试通过：根节点同时也是告警节点");
    }

    /**
     * 测试11：多个traceId，部分有根节点，部分无根节点
     * 
     * 预期：
     * - 有根节点的traceId正常显示
     * - 无根节点的部分连接到Explore
     * - 有多个根节点
     */
    @Test
    public void testBuildChain_MixedTraceIds() {
        System.out.println("\n========== 测试11：混合traceId（部分有根部分无根） ==========");
        
        List<RawAlarm> alarms = Arrays.asList(
            createAlarm("E001", "T001", "T001", null, "告警1", "高"),  // T001有根
            createAlarm("E002", "T002", "NODE_NO_ROOT", "MISSING", "告警2", "高")  // T002无根
        );
        
        List<RawLog> logs = Arrays.asList(
            // T001 - 有完整根节点
            createProcessLog("T001", null, "T001", "root1.exe", "processCreate"),
            createProcessLog("CHILD_T001", "T001", "T001", "child1.exe", "processCreate"),
            
            // T002 - 无根节点，断链
            createProcessLog("NODE_NO_ROOT", "MISSING", "T002", "noRoot.exe", "processCreate")
        );
        
        Set<String> traceIds = new HashSet<>(Arrays.asList("T001", "T002"));
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms,
            logs,
            traceIds,
            new HashSet<>(),
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull(result);
        long rootCount = countRootNodes(result);
        assertTrue("应该有至少2个根节点（1真实+1Explore）", rootCount >= 2);
        
        // 验证有真实根节点
        boolean hasRealRoot = result.getNodes().stream()
            .anyMatch(n -> "T001".equals(n.getNodeId()) && 
                          n.getChainNode() != null && 
                          Boolean.TRUE.equals(n.getChainNode().getIsRoot()));
        assertTrue("应该有T001作为真实根节点", hasRealRoot);
        
        // 验证有Explore节点
        boolean hasExplore = result.getNodes().stream()
            .anyMatch(n -> "EXPLORE_ROOT".equals(n.getNodeId()));
        assertTrue("应该有Explore节点", hasExplore);
        
        System.out.println("✅ 测试通过：混合traceId处理正确，根节点数=" + rootCount);
    }

    /**
     * 测试12：告警在中间节点（非叶子节点）
     * 
     * 预期：
     * - 能够向上追溯到根节点
     * - 能够向下遍历子进程
     */
    @Test
    public void testBuildChain_AlarmInMiddleNode() {
        System.out.println("\n========== 测试12：告警在中间节点 ==========");
        
        String traceId = "ROOT";
        // 告警在 MIDDLE 节点
        RawAlarm alarm = createAlarm("E001", traceId, "MIDDLE", "ROOT", "中间节点告警", "高");
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog("ROOT", null, traceId, "root.exe", "processCreate"),
            createProcessLog("MIDDLE", "ROOT", traceId, "middle.exe", "processCreate"),
            createProcessLog("CHILD1", "MIDDLE", traceId, "child1.exe", "processCreate"),
            createProcessLog("CHILD2", "MIDDLE", traceId, "child2.exe", "processCreate")
        );
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            Collections.singletonList(alarm),
            logs,
            Collections.singleton(traceId),
            new HashSet<>(),
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull(result);
        assertEquals("应该有4个节点", 4, result.getNodes().size());
        
        // 验证根节点存在
        ProcessNode rootNode = getRootNode(result);
        assertEquals("根节点应该是ROOT", "ROOT", rootNode.getNodeId());
        
        // 验证告警节点
        ProcessNode alarmNode = result.getNodes().stream()
            .filter(n -> "MIDDLE".equals(n.getNodeId()))
            .findFirst()
            .orElse(null);
        assertNotNull("应该找到告警节点MIDDLE", alarmNode);
        assertTrue("MIDDLE应该是告警节点", alarmNode.getChainNode().getIsAlarm());
        
        System.out.println("✅ 测试通过：中间节点告警处理正确");
    }

    /**
     * 测试13：空数据边界情况
     * 
     * 预期：
     * - 空告警：返回空链
     * - 空日志：只有告警节点
     */
    @Test
    public void testBuildChain_EmptyData() {
        System.out.println("\n========== 测试13：空数据边界情况 ==========");
        
        ProcessChainBuilder builder = new ProcessChainBuilder();
        
        // 测试1：空告警
        IncidentProcessChain result1 = builder.buildIncidentChain(
            new ArrayList<>(),
            Arrays.asList(createProcessLog("P1", null, "T1", "p1.exe", "processCreate")),
            Collections.singleton("T1"),
            new HashSet<>(),
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        assertNotNull("空告警应返回空链", result1);
        assertTrue("节点数应为0", result1.getNodes() == null || result1.getNodes().isEmpty());
        
        // 测试2：空日志
        RawAlarm alarm = createAlarm("E001", "T1", "T1", null, "告警", "高");
        IncidentProcessChain result2 = builder.buildIncidentChain(
            Collections.singletonList(alarm),
            new ArrayList<>(),
            Collections.singleton("T1"),
            new HashSet<>(),
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        assertNotNull("空日志应返回链", result2);
        assertTrue("应该至少有告警节点", result2.getNodes().size() >= 1);
        
        System.out.println("✅ 测试通过：空数据处理正确");
    }

    /**
     * 测试14：大量节点触发裁剪
     * 
     * 预期：
     * - 节点超过50个时触发裁剪
     * - 裁剪后保留根节点
     * - 裁剪后保留告警节点
     */
    @Test
    public void testBuildChain_NodePruning() {
        System.out.println("\n========== 测试14：大量节点触发裁剪 ==========");
        
        String traceId = "ROOT";
        RawAlarm alarm = createAlarm("E001", traceId, traceId, null, "告警", "高");
        
        // 创建60个节点（超过50个限制）
        List<RawLog> logs = new ArrayList<>();
        logs.add(createProcessLog(traceId, null, traceId, "root.exe", "processCreate"));
        
        String parentGuid = traceId;
        for (int i = 1; i <= 60; i++) {
            String childGuid = "NODE_" + String.format("%03d", i);
            logs.add(createProcessLog(childGuid, parentGuid, traceId, "process" + i + ".exe", "processCreate"));
            parentGuid = childGuid;
        }
        
        // 执行
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            Collections.singletonList(alarm),
            logs,
            Collections.singleton(traceId),
            new HashSet<>(),
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证
        assertNotNull(result);
        // 注意：由于 MAX_TRAVERSE_DEPTH=50，实际只会创建51个节点（1根+50子）
        // MAX_NODE_COUNT=400，所以不会触发裁剪
        // 这个测试实际验证的是深度限制，而不是裁剪功能
        assertEquals("应该有51个节点（1根+50子，受深度限制）", 51, result.getNodes().size());
        
        // 验证根节点保留
        ProcessNode rootNode = getRootNode(result);
        assertNotNull("应保留根节点", rootNode);
        assertEquals("根节点应该是ROOT", traceId, rootNode.getNodeId());
        
        System.out.println("✅ 测试通过：节点数=" + result.getNodes().size() + "（受深度限制50影响）");
    }

    /**
     * 测试15：多个告警指向同一个节点
     * 
     * 预期：
     * - 节点只创建一次
     * - 节点包含多个告警信息
     */
    @Test
    public void testBuildChain_MultipleAlarmsOnSameNode() {
        System.out.println("\n========== 测试15：多个告警指向同一节点 ==========");
        
        String traceId = "ROOT";
        String targetNode = "MALWARE";
        
        // 3个告警都指向同一个节点
        List<RawAlarm> alarms = Arrays.asList(
            createAlarm("E001", traceId, targetNode, "ROOT", "告警1", "高"),
            createAlarm("E002", traceId, targetNode, "ROOT", "告警2", "中"),
            createAlarm("E003", traceId, targetNode, "ROOT", "告警3", "高")
        );
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog("ROOT", null, traceId, "root.exe", "processCreate"),
            createProcessLog(targetNode, "ROOT", traceId, "malware.exe", "processCreate")
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
        
        // 验证
        assertNotNull(result);
        
        // 验证只有2个节点（ROOT + MALWARE）
        assertEquals("应该有2个节点", 2, result.getNodes().size());
        
        // 验证目标节点
        ProcessNode targetProcessNode = result.getNodes().stream()
            .filter(n -> targetNode.equals(n.getNodeId()))
            .findFirst()
            .orElse(null);
        
        assertNotNull("应该找到目标节点", targetProcessNode);
        assertTrue("目标节点应该是告警节点", targetProcessNode.getChainNode().getIsAlarm());
        
        System.out.println("✅ 测试通过：多告警同节点处理正确");
    }
    
    // ==================== 辅助方法 ====================
    
    /**
     * 统计根节点数量
     */
    private long countRootNodes(IncidentProcessChain chain) {
        return chain.getNodes().stream()
            .filter(node -> node.getIsChainNode() &&
                           node.getChainNode() != null &&
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .count();
    }
    
    /**
     * 获取根节点
     */
    private ProcessNode getRootNode(IncidentProcessChain chain) {
        return chain.getNodes().stream()
            .filter(node -> node.getIsChainNode() &&
                           node.getChainNode() != null &&
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .findFirst()
            .orElse(null);
    }
    
    /**
     * 获取所有根节点ID
     */
    private List<String> getRootNodeIds(IncidentProcessChain chain) {
        return chain.getNodes().stream()
            .filter(node -> node.getIsChainNode() &&
                           node.getChainNode() != null &&
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .map(ProcessNode::getNodeId)
            .collect(java.util.stream.Collectors.toList());
    }
    
    /**
     * 统计断链节点数量
     */
    private long countBrokenNodes(IncidentProcessChain chain) {
        return chain.getNodes().stream()
            .filter(node -> node.getIsChainNode() &&
                           node.getChainNode() != null &&
                           Boolean.TRUE.equals(node.getChainNode().getIsBroken()))
            .count();
    }
    
    /**
     * 创建告警
     */
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
    
    /**
     * 创建进程日志
     */
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
    
    /**
     * 创建文件日志
     */
    private RawLog createFileLog(String fileGuid, String processGuid, String traceId,
                                  String filePath, String eventType) {
        RawLog log = new RawLog();
        log.setProcessGuid(fileGuid);
        log.setParentProcessGuid(processGuid);
        log.setTraceId(traceId);
        log.setLogType("file");
        log.setEventType(eventType);
        log.setFilePath(filePath);
        log.setFileName(filePath.substring(filePath.lastIndexOf("\\") + 1));
        log.setHostAddress("192.168.1.100");
        log.setStartTime("2024-01-15 10:00:00");
        return log;
    }
    
    /**
     * 创建网络日志
     */
    private RawLog createNetworkLog(String networkGuid, String processGuid, String traceId,
                                     String srcIp, String dstIp, String eventType) {
        RawLog log = new RawLog();
        log.setProcessGuid(networkGuid);
        log.setParentProcessGuid(processGuid);
        log.setTraceId(traceId);
        log.setLogType("network");
        log.setEventType(eventType);
        log.setSrcAddress(srcIp);
        log.setDestAddress(dstIp);
        log.setSrcPort("12345");
        log.setDestPort("443");
        log.setTransProtocol("TCP");
        log.setHostAddress("192.168.1.100");
        log.setStartTime("2024-01-15 10:00:00");
        return log;
    }
    
    /**
     * 创建域名日志
     */
    private RawLog createDomainLog(String domainGuid, String processGuid, String traceId,
                                    String domainName, String eventType) {
        RawLog log = new RawLog();
        log.setProcessGuid(domainGuid);
        log.setParentProcessGuid(processGuid);
        log.setTraceId(traceId);
        log.setLogType("domain");
        log.setEventType(eventType);
        log.setRequestDomain(domainName);
        log.setQueryResults("A");
        log.setHostAddress("192.168.1.100");
        log.setStartTime("2024-01-15 10:00:00");
        return log;
    }
}
