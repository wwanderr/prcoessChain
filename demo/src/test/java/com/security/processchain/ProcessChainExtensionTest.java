package com.security.processchain;

import com.security.processchain.model.*;
import com.security.processchain.service.*;
import com.security.processchain.util.ProcessChainExtensionUtil;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * 进程链扩展功能测试
 * 测试从根节点向上扩展溯源的功能
 */
public class ProcessChainExtensionTest {
    
    @Mock
    private OptimizedESQueryService esQueryService;
    
    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }
    
    /**
     * 测试1: 基本扩展功能 - 从根节点向上扩展2层
     */
    @Test
    public void testBasicExtension() {
        System.out.println("\n========== 测试1: 基本扩展功能 ==========");
        
        // 准备数据
        String traceId = "T001";
        String originalRootId = "ROOT_001";  // processGuid = traceId
        String parentId = "PARENT_001";
        String grandParentId = "GRAND_PARENT_001";
        String hostAddress = "192.168.1.100";
        
        // 创建原始根节点
        ProcessNode rootNode = createProcessNode(originalRootId, parentId, true, false);
        List<ProcessNode> allNodes = new ArrayList<>();
        allNodes.add(rootNode);
        
        List<ProcessEdge> allEdges = new ArrayList<>();
        
        // 准备映射
        Map<String, String> traceIdToRootMap = new HashMap<>();
        traceIdToRootMap.put(traceId, originalRootId);
        
        Map<String, String> hostToTraceId = new HashMap<>();
        hostToTraceId.put(hostAddress, traceId);
        
        // Mock ES查询 - 返回父节点和祖父节点日志
        List<RawLog> extensionLogs = new ArrayList<>();
        extensionLogs.add(createRawLog(parentId, grandParentId, hostAddress, "T002"));
        extensionLogs.add(createRawLog(grandParentId, null, hostAddress, "T002"));
        
        when(esQueryService.queryLogsByProcessGuids(eq(hostAddress), anyList(), eq(2)))
                .thenReturn(extensionLogs);
        
        // 执行扩展
        Map<String, String> updatedMap = ProcessChainExtensionUtil.performExtension(
                traceIdToRootMap, hostToTraceId, allNodes, allEdges, esQueryService, 2);
        
        // 验证结果
        System.out.println("原始映射: " + traceIdToRootMap);
        System.out.println("更新映射: " + updatedMap);
        System.out.println("节点数量: " + allNodes.size());
        System.out.println("边数量: " + allEdges.size());
        
        // 断言：映射已更新到最顶端节点
        assertEquals("桥接点应该更新到祖父节点", grandParentId, updatedMap.get(traceId));
        
        // 断言：节点数量增加（原始1个 + 父节点 + 祖父节点）
        assertEquals("应该有3个节点", 3, allNodes.size());
        
        // 断言：边数量增加（祖父->父，父->根）
        assertEquals("应该有2条扩展边", 2, allEdges.size());
        
        // 断言：原根节点的 isRoot 被修改为 false
        ProcessNode originalRoot = findNodeById(allNodes, originalRootId);
        assertFalse("原根节点 isRoot 应该为 false", originalRoot.getChainNode().getIsRoot());
        
        // 断言：新根节点（祖父节点）的 isRoot 为 true
        ProcessNode newRoot = findNodeById(allNodes, grandParentId);
        assertTrue("新根节点 isRoot 应该为 true", newRoot.getChainNode().getIsRoot());
        
        // 断言：扩展节点标记正确
        ProcessNode parent = findNodeById(allNodes, parentId);
        assertTrue("父节点应该被标记为扩展节点", parent.getChainNode().getIsExtensionNode());
        assertEquals("父节点扩展深度应该为1", Integer.valueOf(1), parent.getChainNode().getExtensionDepth());
        
        ProcessNode grandParent = findNodeById(allNodes, grandParentId);
        assertTrue("祖父节点应该被标记为扩展节点", grandParent.getChainNode().getIsExtensionNode());
        assertEquals("祖父节点扩展深度应该为2", Integer.valueOf(2), grandParent.getChainNode().getExtensionDepth());
        
        System.out.println("✅ 测试1通过");
    }
    
    /**
     * 测试2: 无父节点情况 - 根节点无需扩展
     */
    @Test
    public void testNoExtensionWhenNoParent() {
        System.out.println("\n========== 测试2: 无父节点情况 ==========");
        
        String traceId = "T001";
        String rootId = "ROOT_001";
        String hostAddress = "192.168.1.100";
        
        // 创建根节点（无父节点）
        ProcessNode rootNode = createProcessNode(rootId, null, true, false);
        List<ProcessNode> allNodes = new ArrayList<>();
        allNodes.add(rootNode);
        
        List<ProcessEdge> allEdges = new ArrayList<>();
        
        Map<String, String> traceIdToRootMap = new HashMap<>();
        traceIdToRootMap.put(traceId, rootId);
        
        Map<String, String> hostToTraceId = new HashMap<>();
        hostToTraceId.put(hostAddress, traceId);
        
        // 执行扩展
        Map<String, String> updatedMap = ProcessChainExtensionUtil.performExtension(
                traceIdToRootMap, hostToTraceId, allNodes, allEdges, esQueryService, 2);
        
        // 验证结果
        System.out.println("映射保持不变: " + updatedMap.get(traceId));
        System.out.println("节点数量: " + allNodes.size());
        
        // 断言：映射未改变
        assertEquals("映射应该保持不变", rootId, updatedMap.get(traceId));
        
        // 断言：节点数量未增加
        assertEquals("节点数量应该保持为1", 1, allNodes.size());
        
        // 断言：边数量未增加
        assertEquals("边数量应该为0", 0, allEdges.size());
        
        // 断言：isRoot 保持为 true
        assertTrue("根节点 isRoot 应该保持为 true", rootNode.getChainNode().getIsRoot());
        
        System.out.println("✅ 测试2通过");
    }
    
    /**
     * 测试3: 断链节点自动跳过
     */
    @Test
    public void testSkipBrokenNode() {
        System.out.println("\n========== 测试3: 断链节点自动跳过 ==========");
        
        String traceId = "T001";
        String brokenNodeId = "BROKEN_001";
        String hostAddress = "192.168.1.100";
        
        // 创建断链节点
        ProcessNode brokenNode = createProcessNode(brokenNodeId, "MISSING_PARENT", false, true);
        List<ProcessNode> allNodes = new ArrayList<>();
        allNodes.add(brokenNode);
        
        List<ProcessEdge> allEdges = new ArrayList<>();
        
        Map<String, String> traceIdToRootMap = new HashMap<>();
        traceIdToRootMap.put(traceId, brokenNodeId);
        
        Map<String, String> hostToTraceId = new HashMap<>();
        hostToTraceId.put(hostAddress, traceId);
        
        // 执行扩展
        Map<String, String> updatedMap = ProcessChainExtensionUtil.performExtension(
                traceIdToRootMap, hostToTraceId, allNodes, allEdges, esQueryService, 2);
        
        // 验证结果
        System.out.println("断链节点被跳过，映射保持不变: " + updatedMap.get(traceId));
        
        // 断言：映射未改变（断链节点不扩展）
        assertEquals("断链节点映射应该保持不变", brokenNodeId, updatedMap.get(traceId));
        
        // 断言：节点数量未增加
        assertEquals("节点数量应该保持为1", 1, allNodes.size());
        
        // 断言：ES查询未被调用
        verify(esQueryService, never()).queryLogsByProcessGuids(anyString(), anyList(), anyInt());
        
        System.out.println("✅ 测试3通过");
    }
    
    /**
     * 测试4: Explore虚拟节点自动跳过
     */
    @Test
    public void testSkipExploreNode() {
        System.out.println("\n========== 测试4: Explore虚拟节点自动跳过 ==========");
        
        String traceId = "T001";
        String exploreNodeId = "EXPLORE_ROOT";
        String hostAddress = "192.168.1.100";
        
        // 创建Explore虚拟节点
        ProcessNode exploreNode = createProcessNode(exploreNodeId, null, true, false);
        List<ProcessNode> allNodes = new ArrayList<>();
        allNodes.add(exploreNode);
        
        List<ProcessEdge> allEdges = new ArrayList<>();
        
        Map<String, String> traceIdToRootMap = new HashMap<>();
        traceIdToRootMap.put(traceId, exploreNodeId);
        
        Map<String, String> hostToTraceId = new HashMap<>();
        hostToTraceId.put(hostAddress, traceId);
        
        // 执行扩展
        Map<String, String> updatedMap = ProcessChainExtensionUtil.performExtension(
                traceIdToRootMap, hostToTraceId, allNodes, allEdges, esQueryService, 2);
        
        // 验证结果
        System.out.println("Explore节点被跳过，映射保持不变: " + updatedMap.get(traceId));
        
        // 断言：映射未改变
        assertEquals("Explore节点映射应该保持不变", exploreNodeId, updatedMap.get(traceId));
        
        // 断言：ES查询未被调用
        verify(esQueryService, never()).queryLogsByProcessGuids(anyString(), anyList(), anyInt());
        
        System.out.println("✅ 测试4通过");
    }
    
    /**
     * 测试5: 只扩展1层（父节点没有祖父节点）
     */
    @Test
    public void testExtensionOnlyOneLevel() {
        System.out.println("\n========== 测试5: 只扩展1层 ==========");
        
        String traceId = "T001";
        String originalRootId = "ROOT_001";
        String parentId = "PARENT_001";
        String hostAddress = "192.168.1.100";
        
        // 创建原始根节点
        ProcessNode rootNode = createProcessNode(originalRootId, parentId, true, false);
        List<ProcessNode> allNodes = new ArrayList<>();
        allNodes.add(rootNode);
        
        List<ProcessEdge> allEdges = new ArrayList<>();
        
        Map<String, String> traceIdToRootMap = new HashMap<>();
        traceIdToRootMap.put(traceId, originalRootId);
        
        Map<String, String> hostToTraceId = new HashMap<>();
        hostToTraceId.put(hostAddress, traceId);
        
        // Mock ES查询 - 只返回父节点（父节点无父节点）
        List<RawLog> extensionLogs = new ArrayList<>();
        extensionLogs.add(createRawLog(parentId, null, hostAddress, "T002"));
        
        when(esQueryService.queryLogsByProcessGuids(eq(hostAddress), anyList(), eq(2)))
                .thenReturn(extensionLogs);
        
        // 执行扩展
        Map<String, String> updatedMap = ProcessChainExtensionUtil.performExtension(
                traceIdToRootMap, hostToTraceId, allNodes, allEdges, esQueryService, 2);
        
        // 验证结果
        System.out.println("扩展1层，映射更新到父节点: " + updatedMap.get(traceId));
        System.out.println("节点数量: " + allNodes.size());
        
        // 断言：映射更新到父节点
        assertEquals("映射应该更新到父节点", parentId, updatedMap.get(traceId));
        
        // 断言：节点数量为2（原始+父节点）
        assertEquals("应该有2个节点", 2, allNodes.size());
        
        // 断言：边数量为1
        assertEquals("应该有1条扩展边", 1, allEdges.size());
        
        // 断言：父节点是新根节点
        ProcessNode parent = findNodeById(allNodes, parentId);
        assertTrue("父节点应该是新根节点", parent.getChainNode().getIsRoot());
        assertEquals("父节点扩展深度应该为1", Integer.valueOf(1), parent.getChainNode().getExtensionDepth());
        
        System.out.println("✅ 测试5通过");
    }
    
    /**
     * 测试6: ES查询返回空（无法扩展）
     */
    @Test
    public void testNoExtensionWhenESReturnsEmpty() {
        System.out.println("\n========== 测试6: ES查询返回空 ==========");
        
        String traceId = "T001";
        String originalRootId = "ROOT_001";
        String hostAddress = "192.168.1.100";
        
        // 创建根节点（有父节点GUID，但ES查不到）
        ProcessNode rootNode = createProcessNode(originalRootId, "MISSING_PARENT", true, false);
        List<ProcessNode> allNodes = new ArrayList<>();
        allNodes.add(rootNode);
        
        List<ProcessEdge> allEdges = new ArrayList<>();
        
        Map<String, String> traceIdToRootMap = new HashMap<>();
        traceIdToRootMap.put(traceId, originalRootId);
        
        Map<String, String> hostToTraceId = new HashMap<>();
        hostToTraceId.put(hostAddress, traceId);
        
        // Mock ES查询 - 返回空列表
        when(esQueryService.queryLogsByProcessGuids(eq(hostAddress), anyList(), eq(2)))
                .thenReturn(new ArrayList<>());
        
        // 执行扩展
        Map<String, String> updatedMap = ProcessChainExtensionUtil.performExtension(
                traceIdToRootMap, hostToTraceId, allNodes, allEdges, esQueryService, 2);
        
        // 验证结果
        System.out.println("ES返回空，映射保持不变: " + updatedMap.get(traceId));
        
        // 断言：映射未改变
        assertEquals("映射应该保持不变", originalRootId, updatedMap.get(traceId));
        
        // 断言：节点数量未增加
        assertEquals("节点数量应该保持为1", 1, allNodes.size());
        
        System.out.println("✅ 测试6通过");
    }
    
    /**
     * 测试7: 多个traceId同时扩展
     */
    @Test
    public void testMultipleTraceIdsExtension() {
        System.out.println("\n========== 测试7: 多个traceId同时扩展 ==========");
        
        String traceId1 = "T001";
        String rootId1 = "ROOT_001";
        String parentId1 = "PARENT_001";
        
        String traceId2 = "T002";
        String rootId2 = "ROOT_002";
        String parentId2 = "PARENT_002";
        
        String hostAddress1 = "192.168.1.100";
        String hostAddress2 = "192.168.1.101";
        
        // 创建两个根节点
        ProcessNode rootNode1 = createProcessNode(rootId1, parentId1, true, false);
        ProcessNode rootNode2 = createProcessNode(rootId2, parentId2, true, false);
        
        List<ProcessNode> allNodes = new ArrayList<>();
        allNodes.add(rootNode1);
        allNodes.add(rootNode2);
        
        List<ProcessEdge> allEdges = new ArrayList<>();
        
        Map<String, String> traceIdToRootMap = new HashMap<>();
        traceIdToRootMap.put(traceId1, rootId1);
        traceIdToRootMap.put(traceId2, rootId2);
        
        Map<String, String> hostToTraceId = new HashMap<>();
        hostToTraceId.put(hostAddress1, traceId1);
        hostToTraceId.put(hostAddress2, traceId2);
        
        // Mock ES查询 - 分别返回两个父节点
        List<RawLog> logs1 = Arrays.asList(createRawLog(parentId1, null, hostAddress1, "T003"));
        List<RawLog> logs2 = Arrays.asList(createRawLog(parentId2, null, hostAddress2, "T004"));
        
        when(esQueryService.queryLogsByProcessGuids(eq(hostAddress1), anyList(), eq(2)))
                .thenReturn(logs1);
        when(esQueryService.queryLogsByProcessGuids(eq(hostAddress2), anyList(), eq(2)))
                .thenReturn(logs2);
        
        // 执行扩展
        Map<String, String> updatedMap = ProcessChainExtensionUtil.performExtension(
                traceIdToRootMap, hostToTraceId, allNodes, allEdges, esQueryService, 2);
        
        // 验证结果
        System.out.println("traceId1映射: " + updatedMap.get(traceId1));
        System.out.println("traceId2映射: " + updatedMap.get(traceId2));
        System.out.println("总节点数: " + allNodes.size());
        
        // 断言：两个映射都更新了
        assertEquals("traceId1映射应该更新", parentId1, updatedMap.get(traceId1));
        assertEquals("traceId2映射应该更新", parentId2, updatedMap.get(traceId2));
        
        // 断言：节点数量增加到4个
        assertEquals("应该有4个节点", 4, allNodes.size());
        
        // 断言：边数量为2
        assertEquals("应该有2条扩展边", 2, allEdges.size());
        
        System.out.println("✅ 测试7通过");
    }
    
    // ========== 辅助方法 ==========
    
    /**
     * 创建测试用的 ProcessNode
     */
    private ProcessNode createProcessNode(String nodeId, String parentGuid, boolean isRoot, boolean isBroken) {
        ProcessNode node = new ProcessNode();
        node.setNodeId(nodeId);
        node.setIsChainNode(true);
        
        ChainNode chainNode = new ChainNode();
        chainNode.setIsRoot(isRoot);
        chainNode.setIsBroken(isBroken);
        
        ProcessEntity processEntity = new ProcessEntity();
        processEntity.setProcessGuid(nodeId);
        processEntity.setParentProcessGuid(parentGuid);
        processEntity.setProcessName("test_process_" + nodeId);
        processEntity.setImage("C:\\test\\" + nodeId + ".exe");
        
        chainNode.setProcessEntity(processEntity);
        node.setChainNode(chainNode);
        
        return node;
    }
    
    /**
     * 创建测试用的 RawLog
     */
    private RawLog createRawLog(String processGuid, String parentGuid, String hostAddress, String traceId) {
        RawLog log = new RawLog();
        log.setProcessGuid(processGuid);
        log.setParentProcessGuid(parentGuid);
        log.setHostAddress(hostAddress);
        log.setTraceId(traceId);
        log.setLogType("process");
        log.setEventType("processCreate");
        log.setProcessName("test_process_" + processGuid);
        log.setImage("C:\\test\\" + processGuid + ".exe");
        log.setStartTime("2025-10-27 10:00:00");
        return log;
    }
    
    /**
     * 根据ID查找节点
     */
    private ProcessNode findNodeById(List<ProcessNode> nodes, String nodeId) {
        return nodes.stream()
                .filter(n -> nodeId.equals(n.getNodeId()))
                .findFirst()
                .orElse(null);
    }
}


