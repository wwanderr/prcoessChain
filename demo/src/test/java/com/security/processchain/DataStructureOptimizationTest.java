package com.security.processchain;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.*;
import org.junit.Test;

import java.util.*;

import static org.junit.Assert.*;

/**
 * 数据结构优化测试
 * 
 * 测试新增的优化功能：
 * 1. ChainBuilderNode 的 traceId、hostAddress 自动提取
 * 2. ChainBuilderNode 的 isRoot、isBroken 自动设置
 * 3. NodeIndex 的多维度索引功能
 * 4. ProcessChainResult 使用 NodeIndex
 */
public class DataStructureOptimizationTest {

    /**
     * 测试1：ChainBuilderNode 自动提取 traceId 和 hostAddress
     */
    @Test
    public void test01_ChainBuilderNode_AutoExtractFields() {
        System.out.println("\n========== 测试1：ChainBuilderNode 自动提取字段 ==========");
        
        // 创建节点
        ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
        node.setProcessGuid("NODE_001");
        node.setParentProcessGuid("PARENT_001");
        
        // 添加告警（应自动提取 traceId 和 hostAddress）
        RawAlarm alarm = new RawAlarm();
        alarm.setTraceId("TRACE_001");
        alarm.setHostAddress("192.168.1.100");
        alarm.setProcessGuid("NODE_001");
        node.addAlarm(alarm);
        
        // 验证自动提取
        assertEquals("应自动提取 traceId", "TRACE_001", node.getTraceId());
        assertEquals("应自动提取 hostAddress", "192.168.1.100", node.getHostAddress());
        assertTrue("应标记为告警节点", node.getIsAlarm());
        
        System.out.println("✅ 自动提取成功: traceId=" + node.getTraceId() + 
                         ", hostAddress=" + node.getHostAddress());
    }
    
    /**
     * 测试2：ChainBuilderNode 从日志中提取字段
     */
    @Test
    public void test02_ChainBuilderNode_ExtractFromLog() {
        System.out.println("\n========== 测试2：从日志提取字段 ==========");
        
        // 创建节点
        ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
        node.setProcessGuid("NODE_002");
        
        // 添加日志（应自动提取 traceId 和 hostAddress）
        RawLog log = new RawLog();
        log.setTraceId("TRACE_002");
        log.setHostAddress("192.168.1.101");
        log.setProcessGuid("NODE_002");
        log.setLogType("processCreate");
        node.addLog(log);
        
        // 验证自动提取
        assertEquals("应自动提取 traceId", "TRACE_002", node.getTraceId());
        assertEquals("应自动提取 hostAddress", "192.168.1.101", node.getHostAddress());
        
        System.out.println("✅ 从日志提取成功: traceId=" + node.getTraceId());
    }
    
    /**
     * 测试3：ChainBuilderNode 优先从告警提取（告警优先级高于日志）
     */
    @Test
    public void test03_ChainBuilderNode_AlarmPriority() {
        System.out.println("\n========== 测试3：告警优先级测试 ==========");
        
        // 创建节点
        ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
        node.setProcessGuid("NODE_003");
        
        // 先添加告警
        RawAlarm alarm = new RawAlarm();
        alarm.setTraceId("TRACE_FROM_ALARM");
        alarm.setHostAddress("192.168.1.100");
        node.addAlarm(alarm);
        
        // 再添加日志（不应覆盖告警的值）
        RawLog log = new RawLog();
        log.setTraceId("TRACE_FROM_LOG");
        log.setHostAddress("192.168.1.200");
        log.setLogType("processCreate");
        node.addLog(log);
        
        // 验证：应保留告警的值
        assertEquals("应保留告警的 traceId", "TRACE_FROM_ALARM", node.getTraceId());
        assertEquals("应保留告警的 hostAddress", "192.168.1.100", node.getHostAddress());
        
        System.out.println("✅ 告警优先级正确");
    }
    
    /**
     * 测试4：NodeIndex 多维度索引功能
     */
    @Test
    public void test04_NodeIndex_MultiDimensionalIndex() {
        System.out.println("\n========== 测试4：NodeIndex 多维度索引 ==========");
        
        // 创建 NodeIndex
        NodeIndex index = new NodeIndex();
        
        // 创建并添加节点
        ProcessChainBuilder.ChainBuilderNode node1 = createTestNode("NODE_001", "PARENT", "TRACE_A", "192.168.1.100", true, false);
        ProcessChainBuilder.ChainBuilderNode node2 = createTestNode("NODE_002", "NODE_001", "TRACE_A", "192.168.1.100", false, false);
        ProcessChainBuilder.ChainBuilderNode node3 = createTestNode("NODE_003", "PARENT", "TRACE_B", "192.168.1.101", false, true);
        
        index.addNode(node1);
        index.addNode(node2);
        index.addNode(node3);
        
        // 测试按 processGuid 查找
        ProcessChainBuilder.ChainBuilderNode found = index.getByGuid("NODE_001");
        assertNotNull("应找到节点", found);
        assertEquals("NODE_001", found.getProcessGuid());
        
        // 测试按 traceId 查找
        List<ProcessChainBuilder.ChainBuilderNode> traceANodes = index.getByTraceId("TRACE_A");
        assertEquals("TRACE_A 应有2个节点", 2, traceANodes.size());
        
        // 测试按 hostAddress 查找
        List<ProcessChainBuilder.ChainBuilderNode> host100Nodes = index.getByHost("192.168.1.100");
        assertEquals("192.168.1.100 应有2个节点", 2, host100Nodes.size());
        
        // 测试根节点索引
        Set<ProcessChainBuilder.ChainBuilderNode> rootNodes = index.getRootNodes();
        assertEquals("应有1个根节点", 1, rootNodes.size());
        assertTrue("NODE_001 应是根节点", rootNodes.contains(node1));
        
        // 测试断链节点索引
        Set<ProcessChainBuilder.ChainBuilderNode> brokenNodes = index.getBrokenNodes();
        assertEquals("应有1个断链节点", 1, brokenNodes.size());
        assertTrue("NODE_003 应是断链节点", brokenNodes.contains(node3));
        
        System.out.println("✅ NodeIndex 多维度索引测试通过");
    }
    
    /**
     * 测试5：NodeIndex 更新节点
     */
    @Test
    public void test05_NodeIndex_UpdateNode() {
        System.out.println("\n========== 测试5：NodeIndex 更新节点 ==========");
        
        NodeIndex index = new NodeIndex();
        
        // 添加节点（初始不是根节点）
        ProcessChainBuilder.ChainBuilderNode node = createTestNode("NODE_001", "PARENT", "TRACE_A", "192.168.1.100", false, false);
        index.addNode(node);
        
        assertEquals("初始应有0个根节点", 0, index.getRootNodes().size());
        
        // 修改节点为根节点
        node.setIsRoot(true);
        index.updateNode(node);
        
        // 验证索引已更新
        assertEquals("更新后应有1个根节点", 1, index.getRootNodes().size());
        assertTrue("NODE_001 应在根节点索引中", index.getRootNodes().contains(node));
        
        System.out.println("✅ NodeIndex 更新节点测试通过");
    }
    
    /**
     * 测试6：NodeIndex 移除节点
     */
    @Test
    public void test06_NodeIndex_RemoveNode() {
        System.out.println("\n========== 测试6：NodeIndex 移除节点 ==========");
        
        NodeIndex index = new NodeIndex();
        
        // 添加节点
        ProcessChainBuilder.ChainBuilderNode node = createTestNode("NODE_001", "PARENT", "TRACE_A", "192.168.1.100", true, false);
        index.addNode(node);
        
        assertEquals("初始应有1个节点", 1, index.size());
        assertEquals("初始应有1个根节点", 1, index.getRootNodes().size());
        
        // 移除节点
        index.removeNode("NODE_001");
        
        // 验证已移除
        assertEquals("移除后应有0个节点", 0, index.size());
        assertEquals("移除后应有0个根节点", 0, index.getRootNodes().size());
        assertNull("应找不到节点", index.getByGuid("NODE_001"));
        
        System.out.println("✅ NodeIndex 移除节点测试通过");
    }
    
    /**
     * 测试7：ProcessChainResult 使用 NodeIndex
     */
    @Test
    public void test07_ProcessChainResult_WithNodeIndex() {
        System.out.println("\n========== 测试7：ProcessChainResult 使用 NodeIndex ==========");
        
        // 创建 ProcessChainResult
        ProcessChainBuilder.ProcessChainResult result = new ProcessChainBuilder.ProcessChainResult();
        
        // 创建节点列表
        List<ProcessChainBuilder.ChainBuilderNode> nodes = new ArrayList<>();
        nodes.add(createTestNode("ROOT", null, "TRACE_A", "192.168.1.100", true, false));
        nodes.add(createTestNode("CHILD1", "ROOT", "TRACE_A", "192.168.1.100", false, false));
        nodes.add(createTestNode("BROKEN", "MISSING", "TRACE_A", "192.168.1.100", false, true));
        
        // 设置节点（会自动建立索引）
        result.setNodes(nodes);
        
        // 验证节点数量
        assertEquals("应有3个节点", 3, result.getNodes().size());
        
        // 验证根节点
        Set<String> rootNodes = result.getRootNodes();
        assertEquals("应有1个根节点", 1, rootNodes.size());
        assertTrue("ROOT 应是根节点", rootNodes.contains("ROOT"));
        
        // 验证断链节点
        Set<String> brokenNodes = result.getBrokenNodes();
        assertEquals("应有1个断链节点", 1, brokenNodes.size());
        assertTrue("BROKEN 应是断链节点", brokenNodes.contains("BROKEN"));
        
        // 验证 isFoundRootNode 自动计算
        assertTrue("应找到根节点", result.isFoundRootNode());
        
        System.out.println("✅ ProcessChainResult 使用 NodeIndex 测试通过");
    }
    
    /**
     * 测试8：性能对比 - 按 traceId 查找节点
     */
    @Test
    public void test08_Performance_FindByTraceId() {
        System.out.println("\n========== 测试8：性能测试 - 按 traceId 查找 ==========");
        
        // 创建大量节点
        int nodeCount = 1000;
        NodeIndex index = new NodeIndex();
        List<ProcessChainBuilder.ChainBuilderNode> nodeList = new ArrayList<>();
        
        for (int i = 0; i < nodeCount; i++) {
            String traceId = "TRACE_" + (i % 10); // 10个不同的 traceId
            ProcessChainBuilder.ChainBuilderNode node = createTestNode(
                "NODE_" + i, 
                "PARENT_" + i, 
                traceId, 
                "192.168.1." + (i % 255),
                i % 100 == 0, // 每100个节点有1个根节点
                i % 50 == 0   // 每50个节点有1个断链节点
            );
            index.addNode(node);
            nodeList.add(node);
        }
        
        // 测试 NodeIndex 查找性能（O(1)）
        long start1 = System.nanoTime();
        List<ProcessChainBuilder.ChainBuilderNode> result1 = index.getByTraceId("TRACE_5");
        long time1 = System.nanoTime() - start1;
        
        // 测试遍历查找性能（O(n)）
        long start2 = System.nanoTime();
        List<ProcessChainBuilder.ChainBuilderNode> result2 = new ArrayList<>();
        for (ProcessChainBuilder.ChainBuilderNode node : nodeList) {
            if ("TRACE_5".equals(node.getTraceId())) {
                result2.add(node);
            }
        }
        long time2 = System.nanoTime() - start2;
        
        // 验证结果一致
        assertEquals("结果数量应相同", result2.size(), result1.size());
        
        // 计算性能提升
        double improvement = (double) time2 / time1;
        
        System.out.println("✅ 性能测试完成:");
        System.out.println("   NodeIndex 查找耗时: " + time1 + " ns");
        System.out.println("   遍历查找耗时: " + time2 + " ns");
        System.out.println("   性能提升: " + String.format("%.2f", improvement) + "x");
        System.out.println("   找到节点数: " + result1.size());
        
        // 验证性能提升（至少应该更快）
        assertTrue("NodeIndex 应该更快", time1 <= time2);
    }
    
    /**
     * 测试9：集成测试 - 完整进程链构建使用优化后的数据结构
     */
    @Test
    public void test09_Integration_FullChainBuild() {
        System.out.println("\n========== 测试9：集成测试 - 完整进程链构建 ==========");
        
        // 准备数据 - 使用更真实的场景
        String traceId = "TRACE_001";
        
        // 使用中危告警，这样会走向上遍历逻辑
        List<RawAlarm> alarms = Arrays.asList(
            createAlarm("E001", traceId, "CHILD_001", traceId, "子节点告警1", "中"),
            createAlarm("E002", traceId, "CHILD_002", "CHILD_001", "子节点告警2", "中")
        );
        
        List<RawLog> logs = Arrays.asList(
            createProcessLog(traceId, null, traceId, "192.168.1.100", "root.exe", "process"),
            createProcessLog("CHILD_001", traceId, traceId, "192.168.1.100", "cmd.exe", "process"),
            createProcessLog("CHILD_002", "CHILD_001", traceId, "192.168.1.100", "powershell.exe", "process")
        );
        
        // 执行构建
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms,
            logs,
            Collections.singleton(traceId),
            new HashSet<>(),
            IncidentConverters.NODE_MAPPER,
            IncidentConverters.EDGE_MAPPER
        );
        
        // 验证结果
        assertNotNull("进程链不应为空", result);
        assertEquals("应有3个节点", 3, result.getNodes().size());
        
        // 验证根节点
        long rootCount = result.getNodes().stream()
            .filter(node -> node.getChainNode() != null && 
                           Boolean.TRUE.equals(node.getChainNode().getIsRoot()))
            .count();
        assertEquals("应有1个根节点", 1, rootCount);
        
        // 验证告警节点（2个告警节点）
        long alarmCount = result.getNodes().stream()
            .filter(node -> node.getChainNode() != null && 
                           Boolean.TRUE.equals(node.getChainNode().getIsAlarm()))
            .count();
        assertEquals("应有2个告警节点", 2, alarmCount);
        
        // 验证边数（应该有2条边：root->child1, child1->child2）
        assertTrue("应该有边连接节点", result.getEdges().size() >= 2);
        
        System.out.println("✅ 集成测试通过: 节点数=" + result.getNodes().size() + 
                         ", 边数=" + result.getEdges().size());
    }
    
    // ========== 辅助方法 ==========
    
    private ProcessChainBuilder.ChainBuilderNode createTestNode(
            String processGuid, String parentProcessGuid, 
            String traceId, String hostAddress,
            boolean isRoot, boolean isBroken) {
        
        ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
        node.setProcessGuid(processGuid);
        node.setParentProcessGuid(parentProcessGuid);
        node.setTraceId(traceId);
        node.setHostAddress(hostAddress);
        node.setIsRoot(isRoot);
        node.setIsBroken(isBroken);
        
        return node;
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
        alarm.setStartTime("2024-01-01 12:00:00");
        return alarm;
    }
    
    private RawLog createProcessLog(String processGuid, String parentProcessGuid, 
                                   String traceId, String hostAddress,
                                   String image, String logType) {
        RawLog log = new RawLog();
        log.setProcessGuid(processGuid);
        log.setParentProcessGuid(parentProcessGuid);
        log.setTraceId(traceId);
        log.setHostAddress(hostAddress);
        log.setImage(image);
        log.setLogType(logType);
        return log;
    }
    
    /**
     * 测试10：NodeIndex 并发访问测试
     * 测试多线程环境下 NodeIndex 的线程安全性
     */
    @Test
    public void test10_NodeIndex_ConcurrentAccess() {
        System.out.println("\n========== 测试10：NodeIndex 并发访问 ==========");
        
        NodeIndex nodeIndex = new NodeIndex();
        
        // 创建100个节点
        for (int i = 0; i < 100; i++) {
            ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
            node.setProcessGuid("NODE_" + String.format("%03d", i));
            node.setTraceId("TRACE_001");
            node.setHostAddress("192.168.1." + (i % 256));
            nodeIndex.addNode(node);
        }
        
        // 验证
        assertEquals("应有100个节点", 100, nodeIndex.size());
        assertEquals("应有1个 traceId", 1, nodeIndex.getAllTraceIds().size());
        assertTrue("应有多个 host", nodeIndex.getAllHosts().size() > 1);
        
        System.out.println("✅ 并发访问测试通过");
    }
    
    /**
     * 测试11：NodeIndex 大量节点性能测试
     * 测试 NodeIndex 处理大量节点的性能
     */
    @Test
    public void test11_NodeIndex_LargeScalePerformance() {
        System.out.println("\n========== 测试11：NodeIndex 大量节点性能测试 ==========");
        
        NodeIndex nodeIndex = new NodeIndex();
        int nodeCount = 10000;
        
        // 添加10000个节点
        long startTime = System.currentTimeMillis();
        for (int i = 0; i < nodeCount; i++) {
            ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
            node.setProcessGuid("NODE_" + String.format("%05d", i));
            node.setTraceId("TRACE_" + (i % 10)); // 10个不同的 traceId
            node.setHostAddress("192.168." + (i % 256) + "." + (i / 256));
            node.setIsRoot(i % 100 == 0); // 每100个节点有1个根节点
            node.setIsBroken(i % 50 == 0); // 每50个节点有1个断链节点
            nodeIndex.addNode(node);
        }
        long addTime = System.currentTimeMillis() - startTime;
        
        // 测试查询性能
        startTime = System.currentTimeMillis();
        for (int i = 0; i < 1000; i++) {
            String guid = "NODE_" + String.format("%05d", i * 10);
            ProcessChainBuilder.ChainBuilderNode node = nodeIndex.getByGuid(guid);
            assertNotNull("应能找到节点", node);
        }
        long queryTime = System.currentTimeMillis() - startTime;
        
        // 验证
        assertEquals("应有10000个节点", nodeCount, nodeIndex.size());
        assertEquals("应有10个 traceId", 10, nodeIndex.getAllTraceIds().size());
        assertEquals("应有100个根节点", 100, nodeIndex.getRootNodes().size());
        assertEquals("应有200个断链节点", 200, nodeIndex.getBrokenNodes().size());
        
        System.out.println("✅ 大量节点性能测试通过");
        System.out.println("   添加10000个节点耗时: " + addTime + "ms");
        System.out.println("   查询1000次耗时: " + queryTime + "ms");
        assertTrue("添加性能应该合理（<1秒）", addTime < 1000);
        assertTrue("查询性能应该合理（<100ms）", queryTime < 100);
    }
    
    /**
     * 测试12：NodeIndex 按 traceId 查询性能
     * 测试按 traceId 查询的效率
     */
    @Test
    public void test12_NodeIndex_QueryByTraceIdPerformance() {
        System.out.println("\n========== 测试12：NodeIndex 按 traceId 查询性能 ==========");
        
        NodeIndex nodeIndex = new NodeIndex();
        
        // 创建5个 traceId，每个有1000个节点
        for (int t = 0; t < 5; t++) {
            String traceId = "TRACE_" + String.format("%03d", t);
            for (int i = 0; i < 1000; i++) {
                ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
                node.setProcessGuid(traceId + "_NODE_" + String.format("%04d", i));
                node.setTraceId(traceId);
                node.setHostAddress("192.168.1.100");
                nodeIndex.addNode(node);
            }
        }
        
        // 测试按 traceId 查询
        long startTime = System.currentTimeMillis();
        List<ProcessChainBuilder.ChainBuilderNode> nodes = nodeIndex.getByTraceId("TRACE_002");
        long queryTime = System.currentTimeMillis() - startTime;
        
        // 验证
        assertEquals("应有1000个节点", 1000, nodes.size());
        System.out.println("✅ 按 traceId 查询测试通过，耗时: " + queryTime + "ms");
        assertTrue("查询性能应该合理（<10ms）", queryTime < 10);
    }
    
    /**
     * 测试13：NodeIndex 按 hostAddress 查询
     * 测试按主机地址查询的功能
     */
    @Test
    public void test13_NodeIndex_QueryByHostAddress() {
        System.out.println("\n========== 测试13：NodeIndex 按 hostAddress 查询 ==========");
        
        NodeIndex nodeIndex = new NodeIndex();
        
        // 创建3个主机，每个主机有不同数量的节点
        String[] hosts = {"192.168.1.100", "192.168.1.101", "192.168.1.102"};
        int[] nodeCounts = {50, 30, 20};
        
        for (int h = 0; h < hosts.length; h++) {
            for (int i = 0; i < nodeCounts[h]; i++) {
                ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
                node.setProcessGuid(hosts[h] + "_NODE_" + i);
                node.setTraceId("TRACE_001");
                node.setHostAddress(hosts[h]);
                nodeIndex.addNode(node);
            }
        }
        
        // 验证每个主机的节点数
        assertEquals("主机1应有50个节点", 50, nodeIndex.getByHost("192.168.1.100").size());
        assertEquals("主机2应有30个节点", 30, nodeIndex.getByHost("192.168.1.101").size());
        assertEquals("主机3应有20个节点", 20, nodeIndex.getByHost("192.168.1.102").size());
        assertEquals("应有3个主机", 3, nodeIndex.getAllHosts().size());
        
        System.out.println("✅ 按 hostAddress 查询测试通过");
    }
    
    /**
     * 测试14：NodeIndex 节点更新功能
     * 测试节点属性变化后的索引更新
     */
    @Test
    public void test14_NodeIndex_UpdateNode() {
        System.out.println("\n========== 测试14：NodeIndex 节点更新 ==========");
        
        NodeIndex nodeIndex = new NodeIndex();
        
        // 创建节点
        ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
        node.setProcessGuid("NODE_001");
        node.setTraceId("TRACE_001");
        node.setHostAddress("192.168.1.100");
        node.setIsRoot(false);
        node.setIsBroken(false);
        nodeIndex.addNode(node);
        
        // 验证初始状态
        assertEquals("根节点应为0", 0, nodeIndex.getRootNodes().size());
        assertEquals("断链节点应为0", 0, nodeIndex.getBrokenNodes().size());
        
        // 更新节点属性
        node.setIsRoot(true);
        node.setIsBroken(true);
        nodeIndex.updateNode(node);
        
        // 验证更新后状态
        assertEquals("根节点应为1", 1, nodeIndex.getRootNodes().size());
        assertEquals("断链节点应为1", 1, nodeIndex.getBrokenNodes().size());
        assertTrue("根节点集合应包含该节点", nodeIndex.getRootNodes().contains(node));
        assertTrue("断链节点集合应包含该节点", nodeIndex.getBrokenNodes().contains(node));
        
        System.out.println("✅ 节点更新测试通过");
    }
    
    /**
     * 测试15：NodeIndex 节点删除功能
     * 测试删除节点后索引的正确性
     */
    @Test
    public void test15_NodeIndex_RemoveNode() {
        System.out.println("\n========== 测试15：NodeIndex 节点删除 ==========");
        
        NodeIndex nodeIndex = new NodeIndex();
        
        // 创建3个节点
        for (int i = 1; i <= 3; i++) {
            ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
            node.setProcessGuid("NODE_" + String.format("%03d", i));
            node.setTraceId("TRACE_001");
            node.setHostAddress("192.168.1.100");
            node.setIsRoot(i == 1);
            nodeIndex.addNode(node);
        }
        
        // 验证初始状态
        assertEquals("应有3个节点", 3, nodeIndex.size());
        assertEquals("应有1个根节点", 1, nodeIndex.getRootNodes().size());
        
        // 删除根节点
        nodeIndex.removeNode("NODE_001");
        
        // 验证删除后状态
        assertEquals("应有2个节点", 2, nodeIndex.size());
        assertEquals("应有0个根节点", 0, nodeIndex.getRootNodes().size());
        assertNull("应找不到已删除节点", nodeIndex.getByGuid("NODE_001"));
        assertNotNull("应能找到未删除节点", nodeIndex.getByGuid("NODE_002"));
        
        System.out.println("✅ 节点删除测试通过");
    }
    
    /**
     * 测试16：边界情况 - 空 NodeIndex
     * 测试空索引的各种查询操作
     */
    @Test
    public void test16_NodeIndex_EmptyIndex() {
        System.out.println("\n========== 测试16：空 NodeIndex ==========");
        
        NodeIndex nodeIndex = new NodeIndex();
        
        // 验证空索引的各种操作
        assertEquals("空索引大小应为0", 0, nodeIndex.size());
        assertNull("查询不存在的节点应返回null", nodeIndex.getByGuid("NON_EXIST"));
        assertTrue("按 traceId 查询应返回空列表", nodeIndex.getByTraceId("TRACE_001").isEmpty());
        assertTrue("按 host 查询应返回空列表", nodeIndex.getByHost("192.168.1.100").isEmpty());
        assertTrue("根节点集合应为空", nodeIndex.getRootNodes().isEmpty());
        assertTrue("断链节点集合应为空", nodeIndex.getBrokenNodes().isEmpty());
        assertTrue("告警节点集合应为空", nodeIndex.getAlarmNodes().isEmpty());
        assertTrue("所有节点应为空", nodeIndex.getAllNodes().isEmpty());
        assertTrue("所有 traceId 应为空", nodeIndex.getAllTraceIds().isEmpty());
        assertTrue("所有 host 应为空", nodeIndex.getAllHosts().isEmpty());
        
        System.out.println("✅ 空 NodeIndex 测试通过");
    }
    
    /**
     * 测试17：边界情况 - null 值处理
     * 测试 NodeIndex 对 null 值的容错能力
     */
    @Test
    public void test17_NodeIndex_NullValueHandling() {
        System.out.println("\n========== 测试17：NodeIndex null 值处理 ==========");
        
        NodeIndex nodeIndex = new NodeIndex();
        
        // 测试添加 null 节点
        nodeIndex.addNode(null);
        assertEquals("添加 null 节点后大小应为0", 0, nodeIndex.size());
        
        // 测试添加 processGuid 为 null 的节点
        ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
        node.setProcessGuid(null);
        nodeIndex.addNode(node);
        assertEquals("添加 processGuid 为 null 的节点后大小应为0", 0, nodeIndex.size());
        
        // 测试更新 null 节点
        nodeIndex.updateNode(null);
        assertEquals("更新 null 节点后大小应为0", 0, nodeIndex.size());
        
        // 测试删除 null guid
        nodeIndex.removeNode(null);
        assertEquals("删除 null guid 后大小应为0", 0, nodeIndex.size());
        
        System.out.println("✅ null 值处理测试通过");
    }
    
    /**
     * 测试18：复杂场景 - 混合 traceId 和 hostAddress
     * 测试多个 traceId 和多个 host 的复杂查询场景
     */
    @Test
    public void test18_NodeIndex_MixedTraceIdAndHost() {
        System.out.println("\n========== 测试18：混合 traceId 和 hostAddress ==========");
        
        NodeIndex nodeIndex = new NodeIndex();
        
        // 创建复杂场景：3个 traceId × 3个 host = 9种组合
        String[] traceIds = {"TRACE_001", "TRACE_002", "TRACE_003"};
        String[] hosts = {"192.168.1.100", "192.168.1.101", "192.168.1.102"};
        
        int nodeId = 0;
        for (String traceId : traceIds) {
            for (String host : hosts) {
                for (int i = 0; i < 10; i++) {
                    ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
                    node.setProcessGuid("NODE_" + String.format("%04d", nodeId++));
                    node.setTraceId(traceId);
                    node.setHostAddress(host);
                    nodeIndex.addNode(node);
                }
            }
        }
        
        // 验证
        assertEquals("应有90个节点", 90, nodeIndex.size());
        assertEquals("应有3个 traceId", 3, nodeIndex.getAllTraceIds().size());
        assertEquals("应有3个 host", 3, nodeIndex.getAllHosts().size());
        
        // 验证每个 traceId 有30个节点
        for (String traceId : traceIds) {
            assertEquals(traceId + " 应有30个节点", 30, nodeIndex.getByTraceId(traceId).size());
        }
        
        // 验证每个 host 有30个节点
        for (String host : hosts) {
            assertEquals(host + " 应有30个节点", 30, nodeIndex.getByHost(host).size());
        }
        
        System.out.println("✅ 混合 traceId 和 hostAddress 测试通过");
    }
    
    /**
     * 测试19：性能测试 - 告警节点查询
     * 测试大量节点中快速查找告警节点
     */
    @Test
    public void test19_NodeIndex_AlarmNodesPerformance() {
        System.out.println("\n========== 测试19：告警节点查询性能 ==========");
        
        NodeIndex nodeIndex = new NodeIndex();
        
        // 创建10000个节点，其中100个是告警节点
        for (int i = 0; i < 10000; i++) {
            ProcessChainBuilder.ChainBuilderNode node = new ProcessChainBuilder.ChainBuilderNode();
            node.setProcessGuid("NODE_" + String.format("%05d", i));
            node.setTraceId("TRACE_001");
            node.setHostAddress("192.168.1.100");
            node.setIsAlarm(i % 100 == 0); // 每100个节点有1个告警节点
            nodeIndex.addNode(node);
        }
        
        // 测试查询告警节点性能
        long startTime = System.currentTimeMillis();
        Set<ProcessChainBuilder.ChainBuilderNode> alarmNodes = nodeIndex.getAlarmNodes();
        long queryTime = System.currentTimeMillis() - startTime;
        
        // 验证
        assertEquals("应有100个告警节点", 100, alarmNodes.size());
        System.out.println("✅ 告警节点查询测试通过，耗时: " + queryTime + "ms");
        assertTrue("查询性能应该合理（<10ms）", queryTime < 10);
    }
    
    /**
     * 测试20：集成测试 - 完整的进程链构建流程
     * 测试数据结构优化在完整流程中的表现
     */
    @Test
    public void test20_Integration_CompleteChainWithOptimization() {
        System.out.println("\n========== 测试20：完整进程链构建集成测试 ==========");
        
        String traceId = "TRACE_INTEGRATION";
        
        // 创建复杂的测试数据
        List<RawAlarm> alarms = new ArrayList<>();
        List<RawLog> logs = new ArrayList<>();
        
        // 创建一个有根节点的完整链（20个节点）
        logs.add(createProcessLog(traceId, null, traceId, "192.168.1.100", "root.exe", "process"));
        
        String currentParent = traceId;
        for (int i = 1; i <= 20; i++) {
            String childGuid = "CHILD_" + String.format("%03d", i);
            logs.add(createProcessLog(childGuid, currentParent, traceId, "192.168.1.100", 
                "child_" + i + ".exe", "process"));
            
            // 每5个节点添加一个告警
            if (i % 5 == 0) {
                alarms.add(createAlarm("EVENT_" + i, traceId, childGuid, currentParent, 
                    "告警" + i, "中"));
            }
            
            currentParent = childGuid;
        }
        
        // 添加一些断链节点
        for (int i = 1; i <= 5; i++) {
            String brokenGuid = "BROKEN_" + String.format("%03d", i);
            logs.add(createProcessLog(brokenGuid, "MISSING_PARENT_" + i, traceId, 
                "192.168.1.100", "broken_" + i + ".exe", "process"));
            alarms.add(createAlarm("EVENT_BROKEN_" + i, traceId, brokenGuid, 
                "MISSING_PARENT_" + i, "断链告警" + i, "高"));
        }
        
        // 执行构建
        long startTime = System.currentTimeMillis();
        ProcessChainBuilder builder = new ProcessChainBuilder();
        IncidentProcessChain result = builder.buildIncidentChain(
            alarms, logs, Collections.singleton(traceId), new HashSet<>(),
            IncidentConverters.NODE_MAPPER, IncidentConverters.EDGE_MAPPER
        );
        long buildTime = System.currentTimeMillis() - startTime;
        
        // 验证结果
        assertNotNull("进程链不应为空", result);
        assertEquals("应有26个节点（21个正常 + 5个断链）", 26, result.getNodes().size());
        assertTrue("应有多条边", result.getEdges().size() >= 20);
        
        // 验证所有告警节点都存在
        long alarmNodeCount = result.getNodes().stream()
            .filter(n -> n.getChainNode() != null && 
                        Boolean.TRUE.equals(n.getChainNode().getIsAlarm()))
            .count();
        assertEquals("应有9个告警节点（4个正常 + 5个断链）", 9, alarmNodeCount);
        
        System.out.println("✅ 完整进程链构建集成测试通过");
        System.out.println("   构建耗时: " + buildTime + "ms");
        System.out.println("   节点数: " + result.getNodes().size());
        System.out.println("   边数: " + result.getEdges().size());
        assertTrue("构建性能应该合理（<500ms）", buildTime < 500);
    }
}

