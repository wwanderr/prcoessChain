package com.security.processchain.util;

import com.security.processchain.model.ProcessEdge;
import com.security.processchain.model.ProcessNode;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * 进程链合法性验证工具类
 * 
 * 核心功能：对合并后的进程链进行合法性检查和修复
 * 
 * 检查项目：
 * 1. 删除指向不存在节点的边
 * 2. 删除自环边
 * 3. 删除重复边
 * 4. 删除无效边（null/空节点）
 * 5. 简单环检测（可选）
 * 
 * @author AI Assistant
 * @since 2025-11-22
 */
@Slf4j
public class ProcessChainValidator {
    
    /**
     * 验证并修复进程链
     * 
     * 使用场景：在合并网侧和端侧进程链后调用
     * 
     * @param nodes 所有节点列表
     * @param edges 所有边列表（会原地修改）
     */
    public static void validateAndFix(List<ProcessNode> nodes, List<ProcessEdge> edges) {
        if (nodes == null || edges == null) {
            log.warn("【合法性检查】-> 输入为空，跳过检查");
            return;
        }
        
        log.info("【合法性检查】-> ========================================");
        log.info("【合法性检查】-> 开始检查，节点数: {}, 边数: {}", nodes.size(), edges.size());
        
        int originalEdgeCount = edges.size();
        
        // 1. 建立节点ID集合
        Set<String> nodeIds = buildNodeIdSet(nodes);
        
        // 2. 删除无效边
        int invalidEdgesBefore = edges.size();
        removeInvalidEdges(edges, nodeIds);
        int invalidEdgesRemoved = invalidEdgesBefore - edges.size();
        
        // 3. 删除自环边
        int selfLoopBefore = edges.size();
        removeSelfLoopEdges(edges);
        int selfLoopRemoved = selfLoopBefore - edges.size();
        
        // 4. 删除重复边
        int duplicateBefore = edges.size();
        removeDuplicateEdges(edges);
        int duplicateRemoved = duplicateBefore - edges.size();
        
        // 5. 简单环检测并自动断开
        int cycleBefore = edges.size();
        int cycleEdgesRemoved = breakSimpleCycles(edges, nodes);
        
        int totalRemoved = originalEdgeCount - edges.size();
        
        // 打印详细统计
        log.info("【合法性检查】-> ========================================");
        log.info("【合法性检查】-> 检查完成统计：");
        log.info("【合法性检查】->   - 删除无效边（节点不存在）: {} 条", invalidEdgesRemoved);
        log.info("【合法性检查】->   - 删除自环边: {} 条", selfLoopRemoved);
        log.info("【合法性检查】->   - 删除重复边: {} 条", duplicateRemoved);
        log.info("【合法性检查】->   - 断开环（删除边）: {} 条", cycleEdgesRemoved);
        log.info("【合法性检查】->   - 总计删除边数: {} 条", totalRemoved);
        log.info("【合法性检查】->   - 剩余边数: {} 条", edges.size());
        log.info("【合法性检查】-> ========================================");
    }
    
    /**
     * 建立节点ID集合（用于快速查找）
     */
    private static Set<String> buildNodeIdSet(List<ProcessNode> nodes) {
        Set<String> nodeIds = new HashSet<>();
        for (ProcessNode node : nodes) {
            if (node != null && node.getNodeId() != null && !node.getNodeId().isEmpty()) {
                nodeIds.add(node.getNodeId());
            }
        }
        log.debug("【合法性检查】-> 有效节点ID数: {}", nodeIds.size());
        return nodeIds;
    }
    
    /**
     * 删除无效边（source 或 target 不存在的边）
     * 
     * 检查规则：
     * 1. 边为 null
     * 2. source 或 target 为 null/空字符串
     * 3. source 或 target 节点不存在
     */
    private static void removeInvalidEdges(List<ProcessEdge> edges, Set<String> nodeIds) {
        int removedCount = 0;
        Iterator<ProcessEdge> iterator = edges.iterator();
        
        while (iterator.hasNext()) {
            ProcessEdge edge = iterator.next();
            
            // 检查1: 边为 null
            if (edge == null) {
                iterator.remove();
                removedCount++;
                continue;
            }
            
            String source = edge.getSource();
            String target = edge.getTarget();
            
            // 检查2: source 或 target 为空
            if (source == null || source.isEmpty()) {
                log.warn("【合法性检查-无效边】删除空source边: source=null, target={}", target);
                iterator.remove();
                removedCount++;
                continue;
            }
            
            if (target == null || target.isEmpty()) {
                log.warn("【合法性检查-无效边】删除空target边: source={}, target=null", source);
                iterator.remove();
                removedCount++;
                continue;
            }
            
            // 检查3: source 节点不存在
            if (!nodeIds.contains(source)) {
                log.warn("【合法性检查-节点不存在】删除边: {} → {} (source不存在)", source, target);
                iterator.remove();
                removedCount++;
                continue;
            }
            
            // 检查4: target 节点不存在
            if (!nodeIds.contains(target)) {
                log.warn("【合法性检查-节点不存在】删除边: {} → {} (target不存在)", source, target);
                iterator.remove();
                removedCount++;
                continue;
            }
        }
        
        if (removedCount > 0) {
            log.info("【合法性检查】-> ✅ 删除无效边: {} 条", removedCount);
        }
    }
    
    /**
     * 删除自环边（source == target）
     * 
     * 例外：虚拟节点（VIRTUAL_、EXPLORE_）的自环会保留并记录警告
     */
    private static void removeSelfLoopEdges(List<ProcessEdge> edges) {
        int removedCount = 0;
        Iterator<ProcessEdge> iterator = edges.iterator();
        
        while (iterator.hasNext()) {
            ProcessEdge edge = iterator.next();
            String source = edge.getSource();
            String target = edge.getTarget();
            
            // 检查是否是自环
            if (source.equals(target)) {
                // 虚拟节点的自环保留（但记录警告）
                if (source.startsWith("VIRTUAL_") || source.startsWith("EXPLORE_")) {
                    log.warn("【合法性检查-自环】检测到虚拟节点自环（保留）: {} → {}", source, target);
                } else {
                    log.warn("【合法性检查-自环】删除自环边: {} → {}", source, target);
                    iterator.remove();
                    removedCount++;
                }
            }
        }
        
        if (removedCount > 0) {
            log.info("【合法性检查】-> ✅ 删除自环边: {} 条", removedCount);
        }
    }
    
    /**
     * 删除重复边（相同 source 和 target）
     * 
     * 保留策略：保留第一次出现的边，删除后续重复的边
     */
    private static void removeDuplicateEdges(List<ProcessEdge> edges) {
        Set<String> edgeSignatures = new HashSet<>();
        int removedCount = 0;
        Iterator<ProcessEdge> iterator = edges.iterator();
        
        while (iterator.hasNext()) {
            ProcessEdge edge = iterator.next();
            String signature = edge.getSource() + "->" + edge.getTarget();
            
            if (edgeSignatures.contains(signature)) {
                log.warn("【合法性检查-重复边】删除重复边: {} → {} (已存在)", 
                        edge.getSource(), edge.getTarget());
                iterator.remove();
                removedCount++;
            } else {
                edgeSignatures.add(signature);
            }
        }
        
        if (removedCount > 0) {
            log.info("【合法性检查】-> ✅ 删除重复边: {} 条", removedCount);
        }
    }
    
    /**
     * 简单环检测（基于双向边检测）
     * 
     * 检测方法：
     * 1. 统计每个节点的出边
     * 2. 检测是否存在双向边：A → B 且 B → A
     * 3. 记录警告日志，但不自动删除（由人工判断）
     * 
     * 注意：这是一个简化的检测方法，只检测简单的双向环
     */
    private static void detectAndReportSimpleCycles(List<ProcessEdge> edges, Set<String> nodeIds) {
        // 构建邻接表
        Map<String, Set<String>> outEdges = new HashMap<>();
        
        for (String nodeId : nodeIds) {
            outEdges.put(nodeId, new HashSet<>());
        }
        
        for (ProcessEdge edge : edges) {
            String source = edge.getSource();
            String target = edge.getTarget();
            outEdges.get(source).add(target);
        }
        
        // 检测简单环：A → B 且 B → A
        Set<String> reportedPairs = new HashSet<>();
        int simpleCycles = 0;
        
        for (ProcessEdge edge : edges) {
            String source = edge.getSource();
            String target = edge.getTarget();
            
            // 检查是否存在反向边
            if (outEdges.get(target).contains(source)) {
                String pairKey = source.compareTo(target) < 0 
                        ? source + "<->" + target 
                        : target + "<->" + source;
                
                if (!reportedPairs.contains(pairKey)) {
                    reportedPairs.add(pairKey);
                    simpleCycles++;
                    log.warn("【合法性检查-环】检测到简单环（双向边）: {} ⇄ {}", source, target);
                }
            }
        }
        
        if (simpleCycles > 0) {
            log.warn("【合法性检查-环】⚠️ 检测到 {} 个简单环（双向边），建议人工检查", simpleCycles);
            log.warn("【合法性检查-环】提示：如需自动断环，可以调用 breakSimpleCycles() 方法");
        }
    }
    
    /**
     * 断掉简单环（可选方法）
     * 
     * 断环策略：
     * 1. 对于双向边 A ⇄ B，保留 A → B，删除 B → A
     * 2. 优先保留告警节点、根节点作为 source 的边
     * 
     * @param edges 边列表（会原地修改）
     * @param nodes 节点列表（用于判断节点重要性）
     * @return 删除的边数量
     */
    public static int breakSimpleCycles(List<ProcessEdge> edges, List<ProcessNode> nodes) {
        // 构建节点映射
        Map<String, ProcessNode> nodeMap = new HashMap<>();
        for (ProcessNode node : nodes) {
            if (node != null && node.getNodeId() != null) {
                nodeMap.put(node.getNodeId(), node);
            }
        }
        
        // 构建邻接表
        Map<String, Set<String>> outEdges = new HashMap<>();
        for (ProcessEdge edge : edges) {
            outEdges.computeIfAbsent(edge.getSource(), k -> new HashSet<>()).add(edge.getTarget());
        }
        
        // 找出双向边对
        Set<String> edgesToRemove = new HashSet<>();
        Set<String> processedPairs = new HashSet<>();
        
        for (ProcessEdge edge : edges) {
            String source = edge.getSource();
            String target = edge.getTarget();
            
            // 检查是否存在反向边
            if (outEdges.containsKey(target) && outEdges.get(target).contains(source)) {
                String pairKey = source.compareTo(target) < 0 
                        ? source + "<->" + target 
                        : target + "<->" + source;
                
                if (!processedPairs.contains(pairKey)) {
                    processedPairs.add(pairKey);
                    
                    // 决定删除哪条边
                    String edgeToRemove = selectEdgeToRemove(source, target, nodeMap);
                    edgesToRemove.add(edgeToRemove);
                    
                    // 打印详细的环信息
                    String[] parts = edgeToRemove.split("->");
                    String removeSource = parts[0];
                    String removeTarget = parts[1];
                    log.warn("【合法性检查-断环】检测到环: {} ⇄ {}", source, target);
                    log.warn("【合法性检查-断环】删除边: {} → {}", removeSource, removeTarget);
                }
            }
        }
        
        // 删除选中的边
        int removedCount = 0;
        Iterator<ProcessEdge> iterator = edges.iterator();
        while (iterator.hasNext()) {
            ProcessEdge edge = iterator.next();
            String signature = edge.getSource() + "->" + edge.getTarget();
            if (edgesToRemove.contains(signature)) {
                log.warn("【合法性检查-断环】实际删除边: {} → {}", 
                        edge.getSource(), edge.getTarget());
                iterator.remove();
                removedCount++;
            }
        }
        
        if (removedCount > 0) {
            log.info("【合法性检查-断环】✅ 断开简单环，删除边数: {}", removedCount);
        }
        
        return removedCount;
    }
    
    /**
     * 从双向边中选择要删除的边
     * 
     * 优先级（优先保留）：
     * 1. 告警节点作为 source
     * 2. 根节点作为 source
     * 3. 桥接边（网侧 → 端侧）
     * 4. 节点ID较小的边（保证确定性）
     */
    private static String selectEdgeToRemove(
            String nodeA, 
            String nodeB, 
            Map<String, ProcessNode> nodeMap) {
        
        ProcessNode nodeAObj = nodeMap.get(nodeA);
        ProcessNode nodeBObj = nodeMap.get(nodeB);
        
        // 优先保留告警节点作为 source 的边
        boolean aIsAlarm = isAlarmNode(nodeAObj);
        boolean bIsAlarm = isAlarmNode(nodeBObj);
        
        if (aIsAlarm && !bIsAlarm) {
            return nodeB + "->" + nodeA; // 删除 B → A，保留 A → B
        }
        if (!aIsAlarm && bIsAlarm) {
            return nodeA + "->" + nodeB; // 删除 A → B，保留 B → A
        }
        
        // 优先保留根节点作为 source 的边
        boolean aIsRoot = isRootNode(nodeAObj);
        boolean bIsRoot = isRootNode(nodeBObj);
        
        if (aIsRoot && !bIsRoot) {
            return nodeB + "->" + nodeA;
        }
        if (!aIsRoot && bIsRoot) {
            return nodeA + "->" + nodeB;
        }
        
        // 优先保留桥接边（网侧 → 端侧）
        boolean aIsStory = nodeAObj != null && nodeAObj.getStoryNode() != null;
        boolean bIsStory = nodeBObj != null && nodeBObj.getStoryNode() != null;
        boolean aIsChain = nodeAObj != null && nodeAObj.getChainNode() != null;
        boolean bIsChain = nodeBObj != null && nodeBObj.getChainNode() != null;
        
        if (aIsStory && bIsChain) {
            return nodeB + "->" + nodeA; // 保留网侧 → 端侧
        }
        if (bIsStory && aIsChain) {
            return nodeA + "->" + nodeB;
        }
        
        // 默认：删除节点ID较大的边（保证确定性）
        return nodeA.compareTo(nodeB) > 0 
                ? nodeA + "->" + nodeB 
                : nodeB + "->" + nodeA;
    }
    
    // ========== 辅助方法 ==========
    
    private static boolean isAlarmNode(ProcessNode node) {
        return node != null && 
               Boolean.TRUE.equals(node.getIsChainNode()) &&
               node.getChainNode() != null && 
               Boolean.TRUE.equals(node.getChainNode().getIsAlarm());
    }
    
    private static boolean isRootNode(ProcessNode node) {
        return node != null && 
               Boolean.TRUE.equals(node.getIsChainNode()) &&
               node.getChainNode() != null && 
               Boolean.TRUE.equals(node.getChainNode().getIsRoot());
    }
}

