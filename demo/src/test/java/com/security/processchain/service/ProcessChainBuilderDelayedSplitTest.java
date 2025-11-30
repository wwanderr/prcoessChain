package com.security.processchain.service;

import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 延迟拆分优化测试
 * 
 * 测试场景：
 * 1. 特殊根节点（processGuid == parentProcessGuid == traceId）
 * 2. 虚拟父节点的创建和调整
 * 3. 父子进程链的构建
 * 4. 实体提取（文件、域名、网络）
 * 5. 告警提取父进程信息
 */
@Slf4j
public class ProcessChainBuilderDelayedSplitTest {

    private ProcessChainGraphBuilder graphBuilder;
    private ProcessChainBuilder chainBuilder;

    @BeforeEach
    public void setUp() {
        graphBuilder = new ProcessChainGraphBuilder();
        chainBuilder = new ProcessChainBuilder();
    }

    /**
     * 测试场景1：特殊根节点 + 虚拟父节点创建
     * 
     * 数据结构：
     * - 告警：MsCpuCN64.exe (processGuid == parentProcessGuid == traceId-205)
     * - 日志：MsCpuCN64.exe 的进程创建日志
     * - 日志：MsCpuCN64.exe 的域名请求日志（实体）
     * 
     * 预期结果：
     * 1. 创建虚拟父节点 VIRTUAL_ROOT_PARENT_2FBB5B6F58FF8A29
     * 2. 虚拟父节点 -> MsCpuCN64.exe
     * 3. 虚拟父节点的 parentProcessGuid 指向根节点（MsCpuCN64.exe）
     * 4. 提取域名实体
     */
    @Test
    public void testSpecialRootNodeWithVirtualParent() {
        log.info("========== 测试场景1：特殊根节点 + 虚拟父节点 ==========");
        
        // ===== 准备测试数据 =====
        List<RawAlarm> alarms = new ArrayList<>();
        List<RawLog> logs = new ArrayList<>();
        
        // 1. 告警：主机域名请求（特殊根节点）
        RawAlarm alarm1 = new RawAlarm();
        alarm1.setEventId("4d21578d9f104dcc9ccb0c065be13c7a");
        alarm1.setProcessGuid("2FBB5B6F58FF8A29");
        alarm1.setParentProcessGuid("2FBB5B6F58FF8A29"); // 特殊：processGuid == parentProcessGuid
        alarm1.setTraceId("traceId-205"); // 特殊：processGuid == traceId
        alarm1.setProcessName("MsCpuCN64.exe");
        alarm1.setImage("C:\\Users\\Administrator\\Downloads\\miner-1\\miner-1\\MsCpuCN64.exe");
        alarm1.setCommandLine("MsCpuCN64.exe -o stratum+tcp://mine.ppxxmr.com:3333 -u 48skiLoCZou6RKRZC8jSPiG6pKMazxMWs4mW61wNs6PzVPQK6dtZQYUJADUybDYgTVLCWRzZfVLegTqMpdhZZW1kUvLxfuw -p x");
        alarm1.setProcessMd5("abc123def456");
        alarm1.setProcessId(5336);
        alarm1.setProcessUserName("DESKTOP-M0S0L3H\\Administrator");
        alarm1.setHostAddress("3.22.22.2");
        alarm1.setHostName("DESKTOP-M0S0L3H");
        alarm1.setLogType("domain");
        alarm1.setOpType("connect");
        alarm1.setRequestDomain("mine.ppxxmr.com");
        alarm1.setAlarmName("Symmi家族挖矿软件回连活动事件");
        alarm1.setSeverity(5);
        alarm1.setStartTime("2025-05-23 17:47:20");
        alarms.add(alarm1);
        
        // 2. 日志：进程创建日志（特殊根节点）
        RawLog log1 = new RawLog();
        log1.setEventId("log-process-2FBB5B6F58FF8A29");
        log1.setProcessGuid("2FBB5B6F58FF8A29");
        log1.setParentProcessGuid("2FBB5B6F58FF8A29"); // 特殊：processGuid == parentProcessGuid
        log1.setTraceId("traceId-205");
        log1.setProcessName("MsCpuCN64.exe");
        log1.setImage("C:\\Users\\Administrator\\Downloads\\miner-1\\miner-1\\MsCpuCN64.exe");
        log1.setCommandLine("MsCpuCN64.exe -o stratum+tcp://mine.ppxxmr.com:3333 -u 48skiLoCZou6RKRZC8jSPiG6pKMazxMWs4mW61wNs6PzVPQK6dtZQYUJADUybDYgTVLCWRzZfVLegTqMpdhZZW1kUvLxfuw -p x");
        log1.setProcessMd5("abc123def456");
        log1.setProcessId(5336);
        log1.setProcessUserName("DESKTOP-M0S0L3H\\Administrator");
        log1.setHostAddress("3.22.22.2");
        log1.setHostName("DESKTOP-M0S0L3H");
        log1.setLogType("process");
        log1.setOpType("create");
        log1.setStartTime("2025-05-23 17:47:19");
        // 父进程信息（用于创建虚拟父节点）
        log1.setParentProcessName("explorer.exe");
        log1.setParentImage("C:\\Windows\\explorer.exe");
        log1.setParentCommandLine("C:\\Windows\\explorer.exe");
        log1.setParentProcessMd5("parent123abc");
        log1.setParentProcessId(1234);
        log1.setParentProcessUserName("DESKTOP-M0S0L3H\\Administrator");
        logs.add(log1);
        
        // 3. 日志：域名请求日志（实体）
        RawLog log2 = new RawLog();
        log2.setEventId("log-domain-2FBB5B6F58FF8A29-1");
        log2.setProcessGuid("2FBB5B6F58FF8A29");
        log2.setParentProcessGuid("2FBB5B6F58FF8A29");
        log2.setTraceId("traceId-205");
        log2.setProcessName("MsCpuCN64.exe");
        log2.setHostAddress("3.22.22.2");
        log2.setHostName("DESKTOP-M0S0L3H");
        log2.setLogType("domain");
        log2.setOpType("connect");
        log2.setRequestDomain("mine.ppxxmr.com");
        log2.setStartTime("2025-05-23 17:47:20");
        logs.add(log2);

        Set<String> traceIds = new HashSet<>();
        traceIds.add("traceId-205");
        
        // ===== 阶段1：建图（不创建虚拟父节点）=====
        log.info("【测试】阶段1：建图...");
        ProcessChainGraph graph = graphBuilder.buildGraph(alarms, logs,traceIds);
        
        log.info("【测试】建图完成: 节点数={}, 边数={}", graph.getNodeCount(), graph.getEdgeCount());
        
        // 验证：此时不应该有虚拟父节点
        assertFalse(graph.hasNode("VIRTUAL_ROOT_PARENT_2FBB5B6F58FF8A29"), 
                "建图阶段不应该创建虚拟父节点");
        
        // 验证：根节点应该存在
        assertTrue(graph.hasNode("2FBB5B6F58FF8A29"), "根节点应该存在");
        
        GraphNode rootNode = graph.getNode("2FBB5B6F58FF8A29");
        assertNotNull(rootNode, "根节点不应该为null");
        assertEquals("2FBB5B6F58FF8A29", rootNode.getProcessGuid());
        assertEquals("2FBB5B6F58FF8A29", rootNode.getParentProcessGuid(), 
                "根节点的 parentProcessGuid 应该保留原值（用于桥接）");
        
        // ===== 阶段2：子图提取 =====
        log.info("【测试】阶段2：子图提取...");
        Set<String> startNodeIds = new HashSet<>();
        startNodeIds.add("2FBB5B6F58FF8A29"); // 从根节点开始
        ProcessChainGraph subgraph = graph.extractSubgraph(startNodeIds);
        
        log.info("【测试】子图提取完成: 节点数={}, 边数={}", 
                subgraph.getNodeCount(), subgraph.getEdgeCount());
        
        // ===== 阶段3：父进程拆分（延迟创建虚拟父节点）=====
        log.info("【测试】阶段3：父进程拆分...");
        createVirtualParentsForSubgraph(subgraph);
        
        log.info("【测试】父进程拆分完成: 节点数={}, 边数={}", 
                subgraph.getNodeCount(), subgraph.getEdgeCount());
        
        // 验证：虚拟父节点应该被创建
        assertTrue(subgraph.hasNode("VIRTUAL_ROOT_PARENT_2FBB5B6F58FF8A29"), 
                "虚拟父节点应该被创建");
        
        GraphNode virtualParent = subgraph.getNode("VIRTUAL_ROOT_PARENT_2FBB5B6F58FF8A29");
        assertNotNull(virtualParent, "虚拟父节点不应该为null");
        assertTrue(virtualParent.isVirtual(), "应该标记为虚拟节点");
        assertEquals("explorer.exe", virtualParent.getProcessName(), 
                "虚拟父节点的进程名应该从日志的 parentProcessName 提取");
        assertEquals("C:\\Windows\\explorer.exe", virtualParent.getImage(), 
                "虚拟父节点的 image 应该从日志的 parentImage 提取");
        
        // 验证：虚拟父节点 -> 根节点的边应该存在
        assertEquals(1, subgraph.getInDegree("2FBB5B6F58FF8A29"), 
                "根节点的入度应该为1（来自虚拟父节点）");
        
        // ===== 阶段4：图分析 =====
        log.info("【测试】阶段4：图分析...");
        traceIds.add("traceId-205");
        subgraph.identifyRootNodes(traceIds);
        
        // 验证：虚拟父节点应该被识别为根节点
        assertTrue(subgraph.getRootNodes().contains("VIRTUAL_ROOT_PARENT_2FBB5B6F58FF8A29"), 
                "虚拟父节点应该被识别为根节点");
        
        // 验证：原根节点的 isRoot 应该被设为 false
        assertFalse(rootNode.isRoot(), 
                "原根节点的 isRoot 应该被设为 false（因为虚拟父节点成为新的根节点）");
        
        // ===== 阶段5：虚拟父节点调整 =====
        log.info("【测试】阶段5：虚拟父节点调整...");
        adjustVirtualParentLinks(subgraph);
        
        // 验证：虚拟父节点的 parentProcessGuid 应该指向根节点
        assertEquals("2FBB5B6F58FF8A29", virtualParent.getParentProcessGuid(), 
                "虚拟父节点的 parentProcessGuid 应该指向根节点（用于桥接）");
        
        // ===== 验证完整的进程链结构 =====
        log.info("【测试】验证进程链结构...");
        log.info("  虚拟父节点: {} (parentProcessGuid={}, isVirtual={}, isRoot={})", 
                virtualParent.getNodeId(), 
                virtualParent.getParentProcessGuid(),
                virtualParent.isVirtual(),
                virtualParent.isRoot());
        log.info("  根节点: {} (parentProcessGuid={}, isRoot={})", 
                rootNode.getNodeId(), 
                rootNode.getParentProcessGuid(),
                rootNode.isRoot());
        
        log.info("========== 测试场景1 通过 ==========\n");
    }

    /**
     * 测试场景2：普通父子进程链 + 实体提取
     * 
     * 数据结构：
     * - cmd.exe (父进程)
     *   └─ AAA.exe (子进程)
     *      └─ notepad.exe (孙进程)
     * - AAA.exe 创建文件 test.txt（文件实体）
     * 
     * 预期结果：
     * 1. 三层进程链
     * 2. 提取文件实体
     * 3. 没有虚拟父节点
     */
    @Test
    public void testNormalProcessChainWithFileEntity() {
        log.info("========== 测试场景2：普通父子进程链 + 文件实体 ==========");
        
        // ===== 准备测试数据 =====
        List<RawAlarm> alarms = new ArrayList<>();
        List<RawLog> logs = new ArrayList<>();
        
        // 1. 日志：cmd.exe 进程创建
        RawLog log1 = new RawLog();
        log1.setEventId("log-cmd-001");
        log1.setProcessGuid("3165C0FB1048A159");
        log1.setParentProcessGuid("PARENT_XXX_001"); // 父进程不在数据中（断链）
        log1.setTraceId("traceId-205");
        log1.setProcessName("cmd.exe");
        log1.setImage("C:\\Windows\\System32\\cmd.exe");
        log1.setCommandLine("cmd.exe -c");
        log1.setProcessMd5("2b40c98ed0f7a1d3b091a3e8353132dc");
        log1.setProcessId(8024);
        log1.setHostAddress("3.22.22.2");
        log1.setHostName("DESKTOP-M0S0L3H");
        log1.setLogType("process");
        log1.setOpType("create");
        log1.setStartTime("2025-05-26 13:25:27");
        logs.add(log1);
        
        // 2. 日志：AAA.exe 进程创建（告警）
        RawAlarm alarm2 = new RawAlarm();
        alarm2.setEventId("1dfbf1a797fd48ffa1180a3c55d7a3f7");
        alarm2.setProcessGuid("9079D76BC6459FC7");
        alarm2.setParentProcessGuid("3165C0FB1048A159"); // 父进程是 cmd.exe
        alarm2.setTraceId("traceId-205");
        alarm2.setProcessName("AAA.exe");
        alarm2.setImage("C:\\Windows\\System32\\whoami.exe");
        alarm2.setCommandLine("aaa");
        alarm2.setProcessMd5("a4a6924f3eaf97981323703d38fd99c4");
        alarm2.setProcessId(4696);
        alarm2.setProcessUserName("DESKTOP-M0S0L3H\\Administrator");
        alarm2.setParentProcessName("cmd.exe");
        alarm2.setParentImage("C:\\Windows\\System32\\cmd.exe");
        alarm2.setParentCommandLine("cmd.exe -c");
        alarm2.setParentProcessMd5("2b40c98ed0f7a1d3b091a3e8353132dc");
        alarm2.setParentProcessId(8024);
        alarm2.setHostAddress("3.22.22.2");
        alarm2.setHostName("DESKTOP-M0S0L3H");
        alarm2.setLogType("process");
        alarm2.setOpType("create");
        alarm2.setStartTime("2025-05-26 13:25:28");
        alarms.add(alarm2);
        
        // 3. 日志：AAA.exe 进程创建（日志，应该与告警合并）
        RawLog log2 = new RawLog();
        log2.setEventId("1dfbf1a797fd48ffa1180a3c55d7a3f7");
        log2.setProcessGuid("9079D76BC6459FC7");
        log2.setParentProcessGuid("3165C0FB1048A159");
        log2.setTraceId("traceId-205");
        log2.setProcessName("AAA.exe");
        log2.setImage("C:\\Windows\\System32\\whoami.exe");
        log2.setCommandLine("aaa");
        log2.setProcessMd5("a4a6924f3eaf97981323703d38fd99c4");
        log2.setProcessId(4696);
        log2.setHostAddress("3.22.22.2");
        log2.setHostName("DESKTOP-M0S0L3H");
        log2.setLogType("process");
        log2.setOpType("create");
        log2.setStartTime("2025-05-26 13:25:28");
        log2.setParentProcessName("cmd.exe");
        log2.setParentImage("C:\\Windows\\System32\\cmd.exe");
        log2.setParentCommandLine("cmd.exe -c");
        log2.setParentProcessMd5("2b40c98ed0f7a1d3b091a3e8353132dc");
        log2.setParentProcessId(8024);
        logs.add(log2);
        
        // 4. 日志：AAA.exe 创建文件（文件实体）
        RawLog log3 = new RawLog();
        log3.setEventId("log-file-001");
        log3.setProcessGuid("9079D76BC6459FC7");
        log3.setParentProcessGuid("3165C0FB1048A159");
        log3.setTraceId("traceId-205");
        log3.setProcessName("AAA.exe");
        log3.setHostAddress("3.22.22.2");
        log3.setHostName("DESKTOP-M0S0L3H");
        log3.setLogType("file");
        log3.setOpType("create");
        log3.setFileName("test.txt");
        log3.setTargetFilename("C:\\Users\\Administrator\\test.txt");
        log3.setFileMd5("file123abc");
        log3.setStartTime("2025-05-26 13:25:29");
        logs.add(log3);
        
        // 5. 日志：notepad.exe 进程创建
        RawLog log4 = new RawLog();
        log4.setEventId("2e0cf2b808fe59ggb2291b4d66e8b4g8");
        log4.setProcessGuid("A1B2C3D4E5F6789A");
        log4.setParentProcessGuid("9079D76BC6459FC7"); // 父进程是 AAA.exe
        log4.setTraceId("traceId-205");
        log4.setProcessName("notepad.exe");
        log4.setImage("C:\\Windows\\System32\\notepad.exe");
        log4.setCommandLine("notepad.exe test.txt");
        log4.setProcessMd5("b4e8c9d1f7a2e3f4a5b6c7d8e9f0a1b2");
        log4.setProcessId(5888);
        log4.setProcessUserName("DESKTOP-M0S0L3H\\Administrator");
        log4.setHostAddress("3.22.22.2");
        log4.setHostName("DESKTOP-M0S0L3H");
        log4.setLogType("process");
        log4.setOpType("create");
        log4.setStartTime("2025-05-26 13:25:29");
        log4.setParentProcessName("AAA.exe");
        log4.setParentImage("C:\\Windows\\System32\\whoami.exe");
        log4.setParentCommandLine("aaa");
        log4.setParentProcessMd5("a4a6924f3eaf97981323703d38fd99c4");
        log4.setParentProcessId(4696);
        logs.add(log4);
        Set<String> traceIds = new HashSet<>();
        traceIds.add("traceId-205");
        
        // ===== 阶段1：建图 =====
        log.info("【测试】阶段1：建图...");
        ProcessChainGraph graph = graphBuilder.buildGraph(alarms, logs,traceIds);
        
        log.info("【测试】建图完成: 节点数={}, 边数={}", graph.getNodeCount(), graph.getEdgeCount());
        
        // 验证：3个进程节点
        assertEquals(3, graph.getNodeCount(), "应该有3个进程节点");
        assertTrue(graph.hasNode("3165C0FB1048A159"), "cmd.exe 应该存在");
        assertTrue(graph.hasNode("9079D76BC6459FC7"), "AAA.exe 应该存在");
        assertTrue(graph.hasNode("A1B2C3D4E5F6789A"), "notepad.exe 应该存在");
        
        // 验证：AAA.exe 应该合并了告警和日志
        GraphNode aaaNode = graph.getNode("9079D76BC6459FC7");
        assertNotNull(aaaNode);
        assertEquals(1, aaaNode.getAlarms().size(), "AAA.exe 应该有1个告警");
        assertEquals(2, aaaNode.getLogs().size(), "AAA.exe 应该有2个日志（进程+文件）");
        
        // 验证：边的关系
        assertEquals(1, graph.getInDegree("9079D76BC6459FC7"), 
                "AAA.exe 的入度应该为1（来自 cmd.exe）");
        assertEquals(1, graph.getInDegree("A1B2C3D4E5F6789A"), 
                "notepad.exe 的入度应该为1（来自 AAA.exe）");
        
        // ===== 验证：不应该创建虚拟父节点（因为不是特殊根节点）=====
        assertFalse(graph.hasNode("VIRTUAL_ROOT_PARENT_3165C0FB1048A159"), 
                "不应该创建虚拟父节点（cmd.exe 不是特殊根节点）");
        assertFalse(graph.hasNode("VIRTUAL_ROOT_PARENT_9079D76BC6459FC7"), 
                "不应该创建虚拟父节点（AAA.exe 不是特殊根节点）");
        
        log.info("========== 测试场景2 通过 ==========\n");
    }

    /**
     * 测试场景3：告警提取父进程信息
     * 
     * 数据结构：
     * - 只有告警，没有日志
     * - 告警包含 parentProcessName, parentImage 等字段
     * 
     * 预期结果：
     * 1. 虚拟父节点从告警提取信息
     * 2. 实体从告警提取
     */
    @Test
    public void testVirtualParentFromAlarmOnly() {
        log.info("========== 测试场景3：告警提取父进程信息 ==========");
        
        // ===== 准备测试数据 =====
        List<RawAlarm> alarms = new ArrayList<>();
        List<RawLog> logs = new ArrayList<>(); // 空日志列表
        
        // 告警：文件创建（特殊根节点）
        RawAlarm alarm1 = new RawAlarm();
        alarm1.setEventId("alarm-file-001");
        alarm1.setProcessGuid("FILE_ROOT_001");
        alarm1.setParentProcessGuid("FILE_ROOT_001"); // 特殊：processGuid == parentProcessGuid
        alarm1.setTraceId("traceId-300"); // 特殊：processGuid == traceId
        alarm1.setProcessName("malware.exe");
        alarm1.setImage("C:\\Temp\\malware.exe");
        alarm1.setCommandLine("malware.exe --evil");
        alarm1.setProcessMd5("malware123");
        alarm1.setProcessId(9999);
        alarm1.setProcessUserName("SYSTEM");
        alarm1.setHostAddress("10.0.0.100");
        alarm1.setHostName("VICTIM-PC");
        alarm1.setLogType("file");
        alarm1.setOpType("create");
        alarm1.setFileName("backdoor.exe");
        alarm1.setTargetFilename("C:\\Windows\\System32\\backdoor.exe");
        alarm1.setFileMd5("backdoor456");
        // 父进程信息（用于创建虚拟父节点）
        alarm1.setParentProcessName("svchost.exe");
        alarm1.setParentImage("C:\\Windows\\System32\\svchost.exe");
        alarm1.setParentCommandLine("svchost.exe -k netsvcs");
        alarm1.setParentProcessMd5("svchost789");
        alarm1.setParentProcessId(1000);
        alarm1.setStartTime("2025-05-26 14:00:00");
        alarms.add(alarm1);

        Set<String> traceIds = new HashSet<>();
        traceIds.add("traceId-205");        // ===== 阶段1：建图 =====
        log.info("【测试】阶段1：建图...");
        ProcessChainGraph graph = graphBuilder.buildGraph(alarms, logs,traceIds);
        
        log.info("【测试】建图完成: 节点数={}, 边数={}", graph.getNodeCount(), graph.getEdgeCount());
        
        // 验证：只有1个节点（malware.exe）
        assertEquals(1, graph.getNodeCount(), "应该有1个进程节点");
        assertTrue(graph.hasNode("FILE_ROOT_001"), "malware.exe 应该存在");
        
        // ===== 阶段2：子图提取 =====
        log.info("【测试】阶段2：子图提取...");
        Set<String> startNodeIds = new HashSet<>();
        startNodeIds.add("FILE_ROOT_001");
        ProcessChainGraph subgraph = graph.extractSubgraph(startNodeIds);
        
        // ===== 阶段3：父进程拆分 =====
        log.info("【测试】阶段3：父进程拆分...");
        createVirtualParentsForSubgraph(subgraph);
        
        log.info("【测试】父进程拆分完成: 节点数={}, 边数={}", 
                subgraph.getNodeCount(), subgraph.getEdgeCount());
        
        // 验证：虚拟父节点应该被创建
        assertTrue(subgraph.hasNode("VIRTUAL_ROOT_PARENT_FILE_ROOT_001"), 
                "虚拟父节点应该被创建");
        
        GraphNode virtualParent = subgraph.getNode("VIRTUAL_ROOT_PARENT_FILE_ROOT_001");
        assertNotNull(virtualParent);
        assertTrue(virtualParent.isVirtual(), "应该标记为虚拟节点");
        
        // 验证：虚拟父节点的信息应该从告警提取
        assertEquals("svchost.exe", virtualParent.getProcessName(), 
                "虚拟父节点的进程名应该从告警的 parentProcessName 提取");
        assertEquals("C:\\Windows\\System32\\svchost.exe", virtualParent.getImage(), 
                "虚拟父节点的 image 应该从告警的 parentImage 提取");
        assertEquals("svchost.exe -k netsvcs", virtualParent.getCommandLine(), 
                "虚拟父节点的 commandLine 应该从告警的 parentCommandLine 提取");
        assertEquals("svchost789", virtualParent.getProcessMd5(), 
                "虚拟父节点的 processMd5 应该从告警的 parentProcessMd5 提取");
        assertEquals(Integer.valueOf(1000), virtualParent.getProcessId(), 
                "虚拟父节点的 processId 应该从告警的 parentProcessId 提取");
        
        log.info("========== 测试场景3 通过 ==========\n");
    }

    // ===== 辅助方法 =====
    
    /**
     * 为子图创建虚拟父节点
     */
    private void createVirtualParentsForSubgraph(ProcessChainGraph subgraph) {
        int createdCount = 0;
        
        for (GraphNode node : subgraph.getAllNodes()) {
            String processGuid = node.getProcessGuid();
            String parentProcessGuid = node.getParentProcessGuid();
            String traceId = node.getTraceId();
            
            // 检测特殊根节点：processGuid == parentProcessGuid == traceId
            if (processGuid != null && parentProcessGuid != null && traceId != null &&
                processGuid.equals(parentProcessGuid) && processGuid.equals(traceId)) {
                
                // 生成虚拟父节点ID
                String virtualParentId = "VIRTUAL_ROOT_PARENT_" + processGuid;
                
                // 如果虚拟父节点还不存在，创建它
                if (!subgraph.hasNode(virtualParentId)) {
                    GraphNode virtualParent = createVirtualParentNode(node);
                    subgraph.addNode(virtualParent);
                    
                    // 创建边：虚拟父节点 → 子根节点
                    subgraph.addEdge(virtualParentId, processGuid);
                    
                    createdCount++;
                    log.info("【父进程拆分】创建虚拟父节点: {} -> {}", virtualParentId, processGuid);
                }
            }
        }
        
        log.info("【父进程拆分】创建虚拟父节点数={}", createdCount);
    }
    
    /**
     * 创建虚拟父节点
     */
    private GraphNode createVirtualParentNode(GraphNode childNode) {
        GraphNode parentNode = new GraphNode();
        
        String virtualParentId = "VIRTUAL_ROOT_PARENT_" + childNode.getProcessGuid();
        parentNode.setNodeId(virtualParentId);
        parentNode.setProcessGuid(virtualParentId);
        parentNode.setParentProcessGuid(null); // 初始为 null，后续会调整
        parentNode.setVirtual(true);
        parentNode.setNodeType("process");
        
        // 从子节点提取父进程信息
        // 优先从日志提取
        if (childNode.getLogs() != null && !childNode.getLogs().isEmpty()) {
            RawLog firstLog = childNode.getLogs().get(0);
            parentNode.setTraceId(firstLog.getTraceId());
            parentNode.setHostAddress(firstLog.getHostAddress());
            parentNode.setProcessName(firstLog.getParentProcessName());
            parentNode.setImage(firstLog.getParentImage());
            parentNode.setCommandLine(firstLog.getParentCommandLine());
            parentNode.setProcessMd5(firstLog.getParentProcessMd5());
            parentNode.setProcessId(firstLog.getParentProcessId());
            parentNode.setProcessUserName(firstLog.getParentProcessUserName());
        } 
        // 没有日志时从告警提取
        else if (childNode.getAlarms() != null && !childNode.getAlarms().isEmpty()) {
            RawAlarm firstAlarm = childNode.getAlarms().get(0);
            parentNode.setTraceId(firstAlarm.getTraceId());
            parentNode.setHostAddress(firstAlarm.getHostAddress());
            parentNode.setProcessName(firstAlarm.getParentProcessName());
            parentNode.setImage(firstAlarm.getParentImage());
            parentNode.setCommandLine(firstAlarm.getParentCommandLine());
            parentNode.setProcessMd5(firstAlarm.getParentProcessMd5());
            parentNode.setProcessId(firstAlarm.getParentProcessId());
            parentNode.setProcessUserName(firstAlarm.getParentProcessUserName());
        }
        
        return parentNode;
    }
    
    /**
     * 调整虚拟父节点的 parentProcessGuid
     */
    private void adjustVirtualParentLinks(ProcessChainGraph subgraph) {
        int adjustedCount = 0;
        Map<String, String> traceIdToRootMap = subgraph.getTraceIdToRootNodeMap();
        
        if (traceIdToRootMap == null || traceIdToRootMap.isEmpty()) {
            log.info("【虚拟父节点调整】没有根节点映射，跳过调整");
            return;
        }
        
        for (GraphNode node : subgraph.getAllNodes()) {
            // 只处理虚拟节点
            if (!node.isVirtual()) {
                continue;
            }
            
            String traceId = node.getTraceId();
            String rootNodeId = traceIdToRootMap.get(traceId);
            
            if (rootNodeId != null) {
                // 有根节点，指向根节点
                node.setParentProcessGuid(rootNodeId);
                adjustedCount++;
                log.debug("【虚拟父节点调整】虚拟节点 {} 的 parentProcessGuid 指向根节点 {}", 
                        node.getNodeId(), rootNodeId);
            } else {
                // 没有根节点，保持 null
                log.debug("【虚拟父节点调整】虚拟节点 {} 的 traceId={} 没有根节点，保持 parentProcessGuid=null", 
                        node.getNodeId(), traceId);
            }
        }
        
        log.info("【虚拟父节点调整】调整虚拟父节点数={}", adjustedCount);
    }
}




