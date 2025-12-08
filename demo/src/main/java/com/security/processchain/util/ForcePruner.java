
package com.security.processchain.util;


import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.GraphNode;
import com.security.processchain.service.NodeType;
import com.security.processchain.service.ProcessChainGraph;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.stream.Collectors;

/**
 * 强制裁剪工具类（兜底机制）
 * 
 * 触发条件：实体过滤后节点数仍然 > 100
 * 目标：强制裁剪到 30 个节点
 * 
 * 策略：
 * 1. 保留网端关联的进程节点 + 它们的向上单链
 * 2. 保留网端关联的实体节点
 * 3. 按 traceId 平分配额（最多3个traceId）
 * 4. 确定性算法：深度优先 + GUID字典序
 * 5. 配额不足时，优先级：网端关联进程 > 单链 > 网端关联实体 > 其他
 * 
 * @author Process Chain Team
 * @version 1.0
 */
@Slf4j
public class ForcePruner {
    
    /** 强制裁剪触发阈值 */
    private static final int FORCE_PRUNE_THRESHOLD = 100;
    
    /** 强制裁剪目标节点数 */
    private static final int FORCE_PRUNE_TARGET = 30;
    
    /** 最多支持的 traceId 数量 */
    private static final int MAX_TRACE_ID_COUNT = 3;
    
    /**
     * 检查是否需要强制裁剪
     * 
     * @param currentNodeCount 当前节点数
     * @return 是否需要强制裁剪
     */
    public static boolean needForcePrune(int currentNodeCount) {
        return currentNodeCount > FORCE_PRUNE_THRESHOLD;
    }
    
    /**
     * 执行强制裁剪（兜底机制）
     * 
     * @param graph 进程链图（包含进程 + 实体节点）
     * @param networkAssociatedEventIds 网端关联的 eventId 集合
     * @param traceIds 所有的 traceId 集合（从外部传入）
     * @return 强制裁剪结果
     */
    public static ForcePruneResult forcePrune(
            ProcessChainGraph graph,
            Set<String> networkAssociatedEventIds,
            Set<String> traceIds) {
        
        int originalCount = graph.getNodeCount();
        log.warn("【强制裁剪】触发兜底机制：当前节点数={} > 阈值={}", 
                originalCount, FORCE_PRUNE_THRESHOLD);
        
        // 步骤1：按 traceId 分组（使用传入的 traceIds）
        Map<String, TraceGroup> traceGroups = groupByTraceId(graph, traceIds);
        log.info("【强制裁剪】traceId 数量: {}", traceGroups.size());
        
        // 步骤2：如果超过3个 traceId，选择前3个（按字典序）
        List<String> selectedTraceIds = selectTopTraceIds(traceGroups, MAX_TRACE_ID_COUNT);
        log.info("【强制裁剪】选择的 traceId: {}", selectedTraceIds);
        
        // 步骤3：计算每个 traceId 的配额
        int quotaPerTrace = FORCE_PRUNE_TARGET / selectedTraceIds.size();
        int remainder = FORCE_PRUNE_TARGET % selectedTraceIds.size();
        log.info("【强制裁剪】每个 traceId 基础配额: {}，余数: {}", 
                quotaPerTrace, remainder);
        
        // 步骤4：为每个 traceId 分配配额并选择节点
        Set<String> nodesToKeep = new LinkedHashSet<>();  // 保持插入顺序
        int traceIndex = 0;
        
        for (String traceId : selectedTraceIds) {
            TraceGroup group = traceGroups.get(traceId);
            
            // 计算该 traceId 的配额（第一个 traceId 分配余数）
            int quota = quotaPerTrace + (traceIndex == 0 ? remainder : 0);
            
            log.info("【强制裁剪】处理 traceId={}, 配额={}", traceId, quota);
            
            // 选择该 traceId 的节点
            Set<String> selectedNodes = selectNodesForTrace(
                group, 
                quota, 
                graph, 
                networkAssociatedEventIds
            );
            
            nodesToKeep.addAll(selectedNodes);
            
            log.info("【强制裁剪】traceId={} 保留节点数: {}", 
                    traceId, selectedNodes.size());
            
            traceIndex++;
        }
        
        // 步骤5：执行裁剪
        int removedCount = 0;
        List<String> allNodeIds = new ArrayList<>(graph.getAllNodes().stream()
                .map(GraphNode::getNodeId)
                .collect(Collectors.toList()));
        
        for (String nodeId : allNodeIds) {
            if (!nodesToKeep.contains(nodeId)) {
                graph.removeCutNode(nodeId);  // ✅ 使用 removeCutNode 方法
                removedCount++;
            }
        }
        
        log.warn("【强制裁剪】完成：原始={}, 保留={}, 移除={}", 
                originalCount, nodesToKeep.size(), removedCount);
        
        return new ForcePruneResult(
            originalCount, 
            nodesToKeep.size(), 
            removedCount
        );
    }
    
    /**
     * 按 traceId 分组
     */
    /**
     * 按 traceId 分组（使用传入的 traceIds）
     * 
     * @param graph 进程链图
     * @param traceIds 所有的 traceId 集合（从外部传入）
     * @return traceId -> TraceGroup 的映射
     */
    private static Map<String, TraceGroup> groupByTraceId(
            ProcessChainGraph graph, 
            Set<String> traceIds) {
        
        // ✅ 使用 TreeMap 确保 traceId 字典序
        Map<String, TraceGroup> groups = new TreeMap<>();
        
        // 为每个传入的 traceId 创建空的 TraceGroup
        for (String traceId : traceIds) {
            groups.put(traceId, new TraceGroup(traceId));
        }
        
        // 遍历所有节点，分配到对应的 traceId 组
        for (GraphNode node : graph.getAllNodes()) {
            String nodeTraceId = node.getTraceId();
            
            // 如果节点的 traceId 在传入的集合中，加入对应的组
            if (nodeTraceId != null && !nodeTraceId.isEmpty() && groups.containsKey(nodeTraceId)) {
                groups.get(nodeTraceId).addNode(node);
            } else {
                // 如果节点没有 traceId 或不在传入集合中，归入 "UNKNOWN" 组
                TraceGroup unknownGroup = groups.computeIfAbsent("UNKNOWN", k -> new TraceGroup("UNKNOWN"));
                unknownGroup.addNode(node);
            }
        }
        
        // 移除空的 TraceGroup（没有节点的组）
        groups.entrySet().removeIf(entry -> entry.getValue().getNodes().isEmpty());
        
        return groups;
    }
    
    /**
     * 选择前 N 个 traceId（按字典序）
     */
    private static List<String> selectTopTraceIds(
            Map<String, TraceGroup> traceGroups, 
            int maxCount) {
        
        // TreeMap 已经按 key 字典序排序，直接取前 N 个
        List<String> traceIds = new ArrayList<>(traceGroups.keySet());
        
        if (traceIds.size() <= maxCount) {
            return traceIds;
        }
        
        return traceIds.subList(0, maxCount);
    }
    
    /**
     * 为单个 traceId 选择节点
     * 
     * 优先级：
     * 1. 网端关联的进程节点
     * 2. 这些进程节点的向上单链
     * 3. 网端关联的实体节点
     * 4. 其他节点（按 DFS + GUID 字典序）
     */
    private static Set<String> selectNodesForTrace(
            TraceGroup group,
            int quota,
            ProcessChainGraph graph,
            Set<String> networkAssociatedEventIds) {
        
        Set<String> result = new LinkedHashSet<>();
        
        // 阶段1：保留网端关联的进程节点及其向上单链
        Set<String> associatedProcessChains = selectAssociatedProcessChains(
            group, 
            graph, 
            networkAssociatedEventIds, 
            quota
        );
        result.addAll(associatedProcessChains);
        
        log.debug("【强制裁剪】traceId={} 网端关联进程链: {} 个", 
                group.getTraceId(), associatedProcessChains.size());
        
        // 阶段2：保留网端关联的实体节点
        int remainingQuota = quota - result.size();
        if (remainingQuota > 0) {
            Set<String> associatedEntities = selectAssociatedEntities(
                group, 
                graph, 
                networkAssociatedEventIds, 
                remainingQuota
            );
            result.addAll(associatedEntities);
            
            log.debug("【强制裁剪】traceId={} 网端关联实体: {} 个", 
                    group.getTraceId(), associatedEntities.size());
        }
        
        // 阶段3：如果还有剩余配额，按 DFS + GUID 字典序选择其他节点
        remainingQuota = quota - result.size();
        if (remainingQuota > 0) {
            Set<String> otherNodes = selectOtherNodesDeterministic(
                group, 
                result, 
                graph, 
                remainingQuota
            );
            result.addAll(otherNodes);
            
            log.debug("【强制裁剪】traceId={} 其他节点: {} 个", 
                    group.getTraceId(), otherNodes.size());
        }
        
        return result;
    }
    
    /**
     * 选择网端关联的进程节点及其向上单链（单链模式）
     * 
     * 说明：一个 traceId 通常只对应一个网端关联的进程节点
     * 策略：只保留第一个网端关联进程节点（GUID 最小的）的向上单链
     */
    private static Set<String> selectAssociatedProcessChains(
            TraceGroup group,
            ProcessChainGraph graph,
            Set<String> networkAssociatedEventIds,
            int maxQuota) {
        
        Set<String> result = new LinkedHashSet<>();
        
        // 1. 找出所有网端关联的进程节点
        List<String> associatedProcessNodes = new ArrayList<>();
        
        for (GraphNode node : group.getNodes()) {
            if (node.getNodeType() == NodeType.PROCESS && 
                isNetworkAssociated(node, networkAssociatedEventIds)) {
                associatedProcessNodes.add(node.getNodeId());
            }
        }
        
        if (associatedProcessNodes.isEmpty()) {
            return result;
        }
        
        // ✅ 按 GUID 排序（确定性）
        Collections.sort(associatedProcessNodes);
        
        log.debug("【强制裁剪】找到 {} 个网端关联进程节点", associatedProcessNodes.size());
        
        // ✅ 修复：只保留第一个网端关联进程节点的向上单链（避免树杈）
        String firstAssociatedProcess = associatedProcessNodes.get(0);
        
        log.info("【强制裁剪】选择第一个网端关联进程（GUID最小）: {}", firstAssociatedProcess);
        
        // 向上追溯到根节点（只保留进程节点）
        List<String> chain = traceToRootProcessOnly(firstAssociatedProcess, graph);
        
        // 检查是否超出配额
        if (chain.size() <= maxQuota) {
            result.addAll(chain);
            log.info("【强制裁剪】保留网端关联进程单链: {} -> 根节点，长度={}", 
                    firstAssociatedProcess, chain.size());
        } else {
            // 配额不足，从根节点开始保留部分链
            int available = maxQuota;
            Collections.reverse(chain);  // 反转：根节点在前
            for (int i = 0; i < available && i < chain.size(); i++) {
                result.add(chain.get(i));
            }
            log.warn("【强制裁剪】网端关联链被截断: 完整长度={}, 保留={}", 
                    chain.size(), available);
        }
        
        // ✅ 检查其他网端关联进程（异常情况）
        if (associatedProcessNodes.size() > 1) {
            log.warn("【强制裁剪】发现多个网端关联进程（异常）: 总数={}, 只保留第一个", 
                    associatedProcessNodes.size());
            
            for (int i = 1; i < associatedProcessNodes.size(); i++) {
                String otherProcess = associatedProcessNodes.get(i);
                if (result.contains(otherProcess)) {
                    log.info("【强制裁剪】其他网端关联进程 {} 已在主链上，已覆盖", otherProcess);
                } else {
                    log.warn("【强制裁剪】其他网端关联进程 {} 不在主链上，已跳过（避免树杈）", otherProcess);
                }
            }
        }
        
        return result;
    }
    
    /**
     * 向上追溯到根节点（只保留进程节点，不保留实体节点）
     */
    private static List<String> traceToRootProcessOnly(String startNodeId, ProcessChainGraph graph) {
        List<String> chain = new ArrayList<>();
        String current = startNodeId;
        Set<String> visited = new HashSet<>();  // 防环
        
        while (current != null && visited.size() < 100) {
            GraphNode node = graph.getNode(current);
            if (node == null) {
                break;
            }
            
            // 只保留进程节点
            if (node.getNodeType() == NodeType.PROCESS) {
                chain.add(current);
                visited.add(current);
            }
            
            // 如果是根节点，停止
            if (graph.getRootNodes().contains(current)) {
                break;
            }
            
            // 获取父节点（只沿进程链向上）
            List<String> parents = graph.getParents(current);
            if (parents.isEmpty()) {
                break;
            }
            
            // ✅ 选择字典序最小的父节点（确定性）
            String nextParent = null;
            for (String parentId : parents) {
                GraphNode parentNode = graph.getNode(parentId);
                if (parentNode != null && parentNode.getNodeType() == NodeType.PROCESS) {
                    if (nextParent == null || parentId.compareTo(nextParent) < 0) {
                        nextParent = parentId;
                    }
                }
            }
            
            current = nextParent;
        }
        
        return chain;
    }
    
    /**
     * 选择网端关联的实体节点及其到根节点的单链
     * 
     * 策略：
     * 1. 找到所有网端关联的实体节点（按 GUID 排序）
     * 2. 保留实体节点本身
     * 3. 追溯实体节点的父进程到根节点的单链
     */
    private static Set<String> selectAssociatedEntities(
            TraceGroup group,
            ProcessChainGraph graph,
            Set<String> networkAssociatedEventIds,
            int maxQuota) {
        
        Set<String> result = new LinkedHashSet<>();
        
        // 收集所有网端关联的实体节点
        List<String> associatedEntities = new ArrayList<>();
        
        for (GraphNode node : group.getNodes()) {
            // 只处理实体节点
            if (node.getNodeType() != NodeType.PROCESS && 
                isNetworkAssociated(node, networkAssociatedEventIds)) {
                associatedEntities.add(node.getNodeId());
            }
        }
        
        if (associatedEntities.isEmpty()) {
            return result;
        }
        
        // ✅ 按 GUID 排序（确定性）
        Collections.sort(associatedEntities);
        
        log.debug("【强制裁剪】找到 {} 个网端关联实体节点", associatedEntities.size());
        
        // ✅ 修复：保留实体节点 + 父进程到根节点的单链
        for (String entityNodeId : associatedEntities) {
            if (result.size() >= maxQuota) {
                log.warn("【强制裁剪】配额已满，停止保留网端关联实体链");
                break;
            }
            
            // 1. 保留实体节点本身
            result.add(entityNodeId);
            log.debug("【强制裁剪】保留网端关联实体: {}", entityNodeId);
            
            // 2. 找到实体节点的父进程节点
            List<String> parents = graph.getParents(entityNodeId);
            
            // 实体节点应该只有一个父进程节点
            String parentProcessId = null;
            for (String parentId : parents) {
                GraphNode parentNode = graph.getNode(parentId);
                if (parentNode != null && parentNode.getNodeType() == NodeType.PROCESS) {
                    parentProcessId = parentId;
                    break;
                }
            }
            
            // 3. 如果找到父进程，追溯到根节点
            if (parentProcessId != null) {
                List<String> chain = traceToRootProcessOnly(parentProcessId, graph);
                
                // 检查配额
                int available = maxQuota - result.size();
                if (available >= chain.size()) {
                    // 配额足够，保留完整链
                    result.addAll(chain);
                    log.debug("【强制裁剪】保留实体 {} 的完整链: {} -> 根节点，长度={}", 
                            entityNodeId, parentProcessId, chain.size());
                } else if (available > 0) {
                    // 配额不足，从根节点开始保留部分链
                    Collections.reverse(chain);  // 反转：根节点在前
                    for (int i = 0; i < available && i < chain.size(); i++) {
                        result.add(chain.get(i));
                    }
                    log.warn("【强制裁剪】实体链被截断: entityId={}, 完整长度={}, 保留={}", 
                            entityNodeId, chain.size(), available);
                    break;
                } else {
                    // 配额已满
                    log.warn("【强制裁剪】配额已满，无法保留实体 {} 的父进程链", entityNodeId);
                    break;
                }
            } else {
                log.warn("【强制裁剪】实体节点 {} 没有找到父进程节点", entityNodeId);
            }
        }
        
        log.debug("【强制裁剪】网端关联实体节点处理完成，共保留 {} 个节点（含单链）", 
                result.size());
        
        return result;
    }
    
    /**
     * 按 DFS + GUID 字典序选择其他节点
     */
    private static Set<String> selectOtherNodesDeterministic(
            TraceGroup group,
            Set<String> excludeNodes,
            ProcessChainGraph graph,
            int quota) {
        
        Set<String> result = new LinkedHashSet<>();
        
        // 找出该 traceId 的根节点
        String rootNode = findRootNodeInGroup(group, graph);
        
        if (rootNode == null) {
            log.warn("【强制裁剪】未找到根节点，按 GUID 排序选择: traceId={}", 
                    group.getTraceId());
            return selectByGuidOrder(group, graph, excludeNodes, quota);
        }
        
        // 如果根节点未被排除，先添加
        if (!excludeNodes.contains(rootNode)) {
            result.add(rootNode);
            log.debug("【强制裁剪】添加根节点: {}", rootNode);
        }
        
        // DFS 遍历（只遍历进程节点）
        dfsSelectProcessNodes(rootNode, graph, excludeNodes, result, quota);
        
        return result;
    }
    
    /**
     * DFS 选择进程节点（单链模式）
     * 
     * 策略：
     * 1. 对子节点按 GUID 升序排序
     * 2. 只选择第一个子节点（GUID 最小的）
     * 3. 继续向下，形成单链，避免树杈
     */
    private static void dfsSelectProcessNodes(
            String currentNodeId,
            ProcessChainGraph graph,
            Set<String> excludeNodes,
            Set<String> result,
            int quota) {
        
        if (result.size() >= quota) {
            return;
        }
        
        // 获取所有子节点
        List<String> children = graph.getChildren(currentNodeId);
        
        // 只保留进程节点
        List<String> processChildren = new ArrayList<>();
        for (String childId : children) {
            GraphNode childNode = graph.getNode(childId);
            if (childNode != null && childNode.getNodeType() == NodeType.PROCESS) {
                processChildren.add(childId);
            }
        }
        
        if (processChildren.isEmpty()) {
            return;
        }
        
        // ✅ 按 GUID 字典序排序（升序，确定性）
        Collections.sort(processChildren);
        
        // ✅ 修复：只选择第一个子节点（GUID 最小的），形成单链
        for (String childId : processChildren) {
            if (result.size() >= quota) {
                return;
            }
            
            // 跳过已排除的节点
            if (excludeNodes.contains(childId) || result.contains(childId)) {
                continue;  // 如果被排除，尝试下一个子节点
            }
            
            result.add(childId);
            log.debug("【强制裁剪】DFS 添加节点（单链）: {} (GUID 最小)", childId);
            
            // 递归处理这个子节点
            dfsSelectProcessNodes(childId, graph, excludeNodes, result, quota);
            
            // ✅ 关键：只选择一个子节点后就返回，不再遍历其他兄弟节点
            // 这样确保形成单链，避免树杈
            return;
        }
    }
    
    /**
     * 找出 traceId 分组中的根节点
     */
    private static String findRootNodeInGroup(TraceGroup group, ProcessChainGraph graph) {
        for (GraphNode node : group.getNodes()) {
            if (graph.getRootNodes().contains(node.getNodeId())) {
                return node.getNodeId();
            }
        }
        return null;
    }
    
    /**
     * 按 GUID 字典序选择节点（兜底策略）
     */
    /**
     * 按 GUID 顺序选择单链（用于没有根节点的场景）
     * 
     * 策略：
     * 1. 找到第一个进程节点（GUID 最小的）
     * 2. 从该节点向下 DFS 选择子节点（单链）
     * 3. 如果配额未用完，添加关联实体
     */
    private static Set<String> selectByGuidOrder(
            TraceGroup group,
            ProcessChainGraph graph,
            Set<String> excludeNodes,
            int quota) {
        
        Set<String> result = new LinkedHashSet<>();
        
        // 1. 找出所有进程节点（排除 excludeNodes）
        List<String> processNodes = new ArrayList<>();
        for (GraphNode node : group.getNodes()) {
            if (!excludeNodes.contains(node.getNodeId()) && 
                node.getNodeType() == NodeType.PROCESS) {
                processNodes.add(node.getNodeId());
            }
        }
        
        if (processNodes.isEmpty()) {
            log.warn("【强制裁剪】GUID 排序：没有可用的进程节点");
            return result;
        }
        
        // 2. 按 GUID 排序（确定性）
        Collections.sort(processNodes);
        
        // 3. 选择第一个进程节点（GUID 最小的）
        String firstProcessNode = processNodes.get(0);
        log.info("【强制裁剪】GUID 排序：选择第一个进程节点: {}", firstProcessNode);
        
        // 4. 从该节点开始 DFS 向下选择（单链）
        result.add(firstProcessNode);
        
        dfsSelectProcessNodes(
                firstProcessNode, 
                graph, 
                excludeNodes, 
                result, 
                quota);
        
        log.info("【强制裁剪】GUID 排序：DFS 选择进程节点完成，数量={}", result.size());
        
        // 5. 如果配额未用完，添加关联实体（按 GUID 排序）
        if (result.size() < quota) {
            List<String> entities = new ArrayList<>();
            for (GraphNode node : group.getNodes()) {
                if (!excludeNodes.contains(node.getNodeId()) && 
                    node.getNodeType() != NodeType.PROCESS &&
                    !result.contains(node.getNodeId())) {
                    entities.add(node.getNodeId());
                }
            }
            
            // 按 GUID 排序（确定性）
            Collections.sort(entities);
            
            // 添加实体节点直到配额用完
            for (String entityId : entities) {
                if (result.size() >= quota) {
                    break;
                }
                result.add(entityId);
                log.debug("【强制裁剪】GUID 排序：添加实体节点: {}", entityId);
            }
        }
        
        log.info("【强制裁剪】GUID 排序：最终选择节点数={}", result.size());
        
        return result;
    }
    
    /**
     * 判断节点是否网端关联
     */
    /**
     * 判断节点是否为网端关联节点（进程或实体）
     * 
     * 逻辑：
     * 1. 实体节点：检查 createdByEventId 是否在 networkAssociatedEventIds 中
     * 2. 进程节点：检查 alarms 和 logs 中的 eventId 是否在 networkAssociatedEventIds 中
     * 
     * @param node 图节点
     * @param networkAssociatedEventIds 网端关联的 eventId 集合
     * @return 是否为网端关联节点
     */
    private static boolean isNetworkAssociated(GraphNode node, Set<String> networkAssociatedEventIds) {
        if (networkAssociatedEventIds == null || networkAssociatedEventIds.isEmpty()) {
            return false;
        }
        
        // 1. 实体节点：检查 createdByEventId
        if (isEntityNode(node.getNodeType())) {
            String createdByEventId = node.getCreatedByEventId();
            if (createdByEventId != null && networkAssociatedEventIds.contains(createdByEventId)) {
                return true;
            }
        }
        
        // 2. 进程节点：检查 alarms 中的 eventId
        if (node.getAlarms() != null) {
            for (RawAlarm alarm : node.getAlarms()) {
                if (alarm.getEventId() != null && networkAssociatedEventIds.contains(alarm.getEventId())) {
                    return true;
                }
            }
        }
        
        // 3. 进程节点：检查 logs 中的 eventId
        if (node.getLogs() != null) {
            for (RawLog log : node.getLogs()) {
                if (log.getEventId() != null && networkAssociatedEventIds.contains(log.getEventId())) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * 判断节点类型是否为实体节点
     */
    private static boolean isEntityNode(String nodeType) {
        if (nodeType == null) {
            return false;
        }
        return nodeType.contains("entity") || 
               nodeType.equals("file") || 
               nodeType.equals("domain") || 
               nodeType.equals("network") || 
               nodeType.equals("registry");
    }
    
    // ========== 辅助类 ==========
    
    /**
     * TraceId 分组
     */
    private static class TraceGroup {
        private final String traceId;
        private final List<GraphNode> nodes;
        
        public TraceGroup(String traceId) {
            this.traceId = traceId;
            this.nodes = new ArrayList<>();
        }
        
        public void addNode(GraphNode node) {
            nodes.add(node);
        }
        
        public String getTraceId() {
            return traceId;
        }
        
        public List<GraphNode> getNodes() {
            return nodes;
        }
    }
    
    /**
     * 强制裁剪结果
     */
    public static class ForcePruneResult {
        private final int originalCount;
        private final int finalCount;
        private final int removedCount;
        
        public ForcePruneResult(int originalCount, int finalCount, int removedCount) {
            this.originalCount = originalCount;
            this.finalCount = finalCount;
            this.removedCount = removedCount;
        }
        
        public int getOriginalCount() {
            return originalCount;
        }
        
        public int getFinalCount() {
            return finalCount;
        }
        
        public int getRemovedCount() {
            return removedCount;
        }
        
        @Override
        public String toString() {
            return String.format("ForcePruneResult{original=%d, final=%d, removed=%d}", 
                    originalCount, finalCount, removedCount);
        }
    }
}

