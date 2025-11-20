package com.security.processchain.service;

import com.security.processchain.constants.ProcessChainConstants;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.util.EntityFilterUtil;
import com.security.processchain.util.ProcessChainPruner;
import com.security.processchain.util.PruneContext;
import com.security.processchain.util.PruneResult;
import lombok.extern.slf4j.Slf4j;
import java.util.*;

// 注意：以下类虽然在文件末尾有 @Deprecated 别名定义，但为了避免IDE报错，这里不显式导入
// 因为它们现在既是独立的类（在 com.security.processchain.service 包中），
// 又在当前类中有内部类别名，Java允许这种情况

/**
 * 进程链构建器
 * 核心类,负责根据告警和日志构建进程链
 */
@Slf4j
public class ProcessChainBuilder {
    
    // 最大遍历深度限制,防止环导致死循环
    private static final int MAX_TRAVERSE_DEPTH = ProcessChainConstants.Limits.MAX_TRAVERSE_DEPTH;
    
    // 节点数量上限
    private static final int MAX_NODE_COUNT = ProcessChainConstants.Limits.MAX_NODE_COUNT;
    
    // 存储所有节点, key为processGuid
    private Map<String, ChainBuilderNode> nodeMap;
    
    // 存储所有边
    private List<ChainBuilderEdge> edges;
    
    // 边去重集合: 使用 "source->target" 作为 key，快速判断边是否已存在
    private Set<String> edgeKeySet;
    
    // 根节点集合
    private Set<String> rootNodes;
    
    // 是否找到了根节点
    private boolean foundRootNode;
    
    // 已访问节点集合,用于检测环（当前递归路径内）
    private Set<String> visitedNodesInPath;
    
    // 向上遍历过程中，已完整处理过的节点（图级 visited，避免重复 DFS）
    private Set<String> globalVisitedUp;
    
    // 向下遍历过程中，已完整处理过的节点（图级 visited，避免重复 DFS）
    private Set<String> globalVisitedDown;
    
    // 网端关联成功的告警eventId集合
    private Set<String> associatedEventIds;
    
    // 已经输出过自环告警的节点集合，用于限制自环日志的重复输出
    private Set<String> selfLoopWarned;
    
    // 断裂节点集合（找不到根节点的最顶端节点）
    private Set<String> brokenNodes;
    
    // 断链节点到 traceId 的映射（用于将断链连接到正确的 EXPLORE）
    private Map<String, String> brokenNodeToTraceId;
    
    // traceId 到根节点ID的映射（用于网端桥接）
    private Map<String, String> traceIdToRootNodeMap;
    
    public ProcessChainBuilder() {
        this.nodeMap = new HashMap<>();
        this.edges = new ArrayList<>();
        this.edgeKeySet = new HashSet<>();
        this.rootNodes = new HashSet<>();
        this.foundRootNode = false;
        this.visitedNodesInPath = new HashSet<>();
        this.globalVisitedUp = new HashSet<>();
        this.globalVisitedDown = new HashSet<>();
        this.associatedEventIds = new HashSet<>();
        this.brokenNodes = new HashSet<>();
        this.brokenNodeToTraceId = new HashMap<>();
        this.traceIdToRootNodeMap = new HashMap<>();
        this.selfLoopWarned = new HashSet<>();
    }
    
    /**
     * 获取 traceId 到根节点ID的映射
     * 用于网端桥接时创建桥接边
     * 
     * @return traceId 到根节点ID的映射（返回副本，防止外部修改）
     */
    public Map<String, String> getTraceIdToRootNodeMap() {
        return new HashMap<>(traceIdToRootNodeMap);
    }
    
    /**
     * 构建进程链（建图方案）
     * 
     * @param alarms 选举出的告警组
     * @param logs 查询到的原始日志
     * @param traceIds 溯源ID集合（支持多个 traceId）
     * @param associatedEventIds 网端关联成功的eventId集合(可为null)
     * @param startLogEventIds 无告警场景的起点日志eventId集合(可为null)
     * @return 构建结果
     */
    public ProcessChainResult buildProcessChain(List<RawAlarm> alarms, List<RawLog> logs, 
                                                Set<String> traceIds, Set<String> associatedEventIds,
                                                Set<String> startLogEventIds) {
        // 允许无告警场景（只有日志）
        if ((alarms == null || alarms.isEmpty()) && (logs == null || logs.isEmpty())) {
            log.warn("【进程链生成】-> 警告: 告警和日志都为空,返回空进程链");
            return new ProcessChainResult();
        }
        
        if (traceIds == null || traceIds.isEmpty()) {
            log.error("【进程链生成】-> 错误: traceIds为空,无法构建进程链");
            return new ProcessChainResult();
        }
        
        try {
            log.info("【进程链生成】-> 开始构建进程链: traceIds={}, 告警数={}, 日志数={}", 
                    traceIds, 
                    alarms != null ? alarms.size() : 0, 
                    logs != null ? logs.size() : 0);
            
            // 记录网端关联的eventIds
            if (associatedEventIds != null && !associatedEventIds.isEmpty()) {
                this.associatedEventIds.addAll(associatedEventIds);
                log.info("【进程链生成】-> 记录网端关联eventIds: {}", associatedEventIds);
            }
            
            // ===== 阶段1：建图 =====
            ProcessChainGraphBuilder graphBuilder = new ProcessChainGraphBuilder();
            ProcessChainGraph fullGraph = graphBuilder.buildGraph(
                    alarms != null ? alarms : Collections.emptyList(),
                    logs != null ? logs : Collections.emptyList(),
                    traceIds
            );
            
            log.info("【建图完成】节点数={}, 根节点={}, 断链节点={}",
                    fullGraph.getNodeCount(),
                    fullGraph.getRootNodes().size(),
                    fullGraph.getBrokenNodes().size());
            
            // ===== 阶段2：确定起点节点 =====
            Set<String> startNodes = new HashSet<>();
            
            // 2.1 有告警场景：以告警节点为起点
            if (alarms != null && !alarms.isEmpty()) {
            for (RawAlarm alarm : alarms) {
                    if (alarm != null && alarm.getProcessGuid() != null) {
                        startNodes.add(alarm.getProcessGuid());
                    }
                }
                log.info("【有告警场景】使用告警节点作为起点: {}", startNodes.size());
            }
            // 2.2 无告警场景：使用指定日志的processGuid作为起点
            else if (startLogEventIds != null && !startLogEventIds.isEmpty()) {
                // 根据eventId找到对应的日志，获取其processGuid
                Map<String, String> eventIdToProcessGuid = new HashMap<>();
                
                if (logs != null) {
                    for (RawLog log : logs) {
                        if (log != null && log.getEventId() != null && 
                            startLogEventIds.contains(log.getEventId())) {
                            eventIdToProcessGuid.put(log.getEventId(), log.getProcessGuid());
                        }
                    }
                }
                
                // 在图中找到对应的节点
                for (String eventId : startLogEventIds) {
                    String processGuid = eventIdToProcessGuid.get(eventId);
                    if (processGuid != null && fullGraph.hasNode(processGuid)) {
                        startNodes.add(processGuid);
                        log.info("【无告警场景】找到起点日志: eventId={}, processGuid={}", 
                                eventId, processGuid);
                    } else {
                        log.warn("【无告警场景】未找到起点日志对应的节点: eventId={}", eventId);
                    }
                }
                
                log.info("【无告警场景】使用指定日志作为起点: eventIds={}, 节点数={}", 
                        startLogEventIds, startNodes.size());
            }
            // 2.3 兜底：使用根节点
            else {
                startNodes.addAll(fullGraph.getRootNodes());
                log.warn("【兜底场景】无告警也无指定日志，使用根节点作为起点: {}", startNodes.size());
            }
            
            log.info("【起点节点】共 {} 个起点", startNodes.size());
            
            // ===== 阶段3：子图提取（遍历） =====
            // 从告警/起点日志出发，提取所有连通的节点
            Set<String> relevantNodes = new HashSet<>();
            
            for (String startNode : startNodes) {
                GraphNode node = fullGraph.getNode(startNode);
                
                if (node == null) {
                    log.warn("【子图提取】起点节点不存在: {}", startNode);
                    continue;
                }
                
                // 全树遍历：向上到root，对路径上每个节点向下遍历所有子树
                // 保证所有连通关系（包括兄弟分支）都被包含
                Set<String> connectedNodes = fullGraph.fullTreeTraversal(startNode);
                relevantNodes.addAll(connectedNodes);
                
                log.info("【全树遍历】起点={}, 连通节点数={}", startNode, connectedNodes.size());
            }
            
            log.info("【子图提取】相关节点总数={}", relevantNodes.size());
            
            // ===== 阶段4：提取子图 =====
            ProcessChainGraph subgraph = fullGraph.extractSubgraph(relevantNodes);
            
            log.info("【子图提取完成】节点数={}", subgraph.getNodeCount());
            
            // ===== 阶段5：实体过滤 =====
            EntityFilterUtil.filterEntityNodesInGraph(subgraph);
            
            log.info("【实体过滤完成】节点数={}", subgraph.getNodeCount());
            
            // ===== 阶段6：裁剪（如果需要） =====
            if (subgraph.getNodeCount() > MAX_NODE_COUNT) {
                log.warn("【智能裁剪】节点数({})超过限制({}), 开始裁剪...", 
                        subgraph.getNodeCount(), MAX_NODE_COUNT);
                pruneGraph(subgraph);
                log.info("【智能裁剪完成】裁剪后节点数={}", subgraph.getNodeCount());
            }
            
            // ===== 阶段7：转换为输出格式 =====
            ProcessChainResult result = convertGraphToResult(subgraph, traceIds);
            
            // ✅ 关键修复：将图中的关键映射同步到 ProcessChainBuilder 的实例变量
            // 这样外部可以通过 getter 方法获取这些映射
            this.traceIdToRootNodeMap = result.getTraceIdToRootNodeMap();
            this.brokenNodeToTraceId = result.getBrokenNodeToTraceId();
            this.rootNodes = result.getRootNodes();
            this.brokenNodes = result.getBrokenNodes();
            
            log.info("进程链构建完成: 节点数={}, 边数={}, 根节点数={}, 断裂节点数={}", 
                    result.getNodes().size(), result.getEdges().size(), 
                    result.getRootNodes().size(), result.getBrokenNodes().size());
            
            log.info("关键映射同步完成: traceIdToRootNodeMap={}, brokenNodeToTraceId={}, rootNodes={}, brokenNodes={}", 
                    this.traceIdToRootNodeMap.size(), this.brokenNodeToTraceId.size(), 
                    this.rootNodes.size(), this.brokenNodes.size());
            
            return result;
            
        } catch (Exception e) {
            log.error("错误: 构建进程链过程异常: {}", e.getMessage(), e);
            return new ProcessChainResult();
        }
    }
    
    /**
     * 裁剪图（智能裁剪策略）
     * 
     * 策略：
     * 1. 强制保留：根节点、告警节点、网端关联节点
     * 2. 级联保留：从关键节点到根节点的完整路径
     * 3. 选择性保留：如果还有剩余槽位，按重要性选择其他节点
     * 
     * @param graph 要裁剪的图
     */
    private void pruneGraph(ProcessChainGraph graph) {
        if (graph == null) {
            return;
        }
        
        try {
            // 1. 将图转换为可裁剪的格式
            Map<String, ChainBuilderNode> nodeMap = new HashMap<>();
            List<ChainBuilderEdge> edges = new ArrayList<>();
            
            // 转换节点
            for (GraphNode graphNode : graph.getAllNodes()) {
                ChainBuilderNode node = convertGraphNodeToBuilderNode(graphNode);
                nodeMap.put(node.getProcessGuid(), node);
            }
            
            // 转换边
            for (String edgeKey : graph.getAllEdgeKeys()) {
                String[] parts = edgeKey.split("->");
                if (parts.length == 2) {
                    ChainBuilderEdge edge = new ChainBuilderEdge();
                    edge.setSource(parts[0]);
                    edge.setTarget(parts[1]);
                    
                    EdgeInfo edgeInfo = graph.getEdgeInfo(edgeKey);
                    if (edgeInfo != null) {
                        edge.setVal(edgeInfo.getLabel());
                    }
                    
                    edges.add(edge);
                }
            }
            
            // 2. 创建裁剪上下文
            PruneContext context = new PruneContext(
                nodeMap,
                edges,
                graph.getRootNodes(),
                this.associatedEventIds
            );
            
            // 3. 执行裁剪
            PruneResult result = ProcessChainPruner.pruneNodes(context);
            
            log.info("【智能裁剪】原始节点={}, 必须保留={}, 级联保留={}, 移除节点={}, 最终节点={}",
                     result.getOriginalNodeCount(),
                     result.getMustKeepCount(),
                     result.getCascadeKeepCount(),
                     result.getRemovedNodeCount(),
                     result.getFinalNodeCount());
            
            // 4. 应用裁剪结果到图
            Set<String> nodesToKeep = nodeMap.keySet();
            Set<String> nodesToRemove = new HashSet<>();
            
            for (GraphNode graphNode : graph.getAllNodes()) {
                String nodeId = graphNode.getNodeId();
                if (!nodesToKeep.contains(nodeId)) {
                    nodesToRemove.add(nodeId);
                }
            }
            
            // 移除被裁剪的节点
            for (String nodeId : nodesToRemove) {
                graph.removeNode(nodeId);
            }
            
            log.info("【图裁剪完成】移除节点数={}", nodesToRemove.size());
            
        } catch (Exception e) {
            log.error("【图裁剪异常】{}", e.getMessage(), e);
            // 裁剪失败不影响主流程，继续执行
        }
    }
    
    /**
     * 将图转换为ProcessChainResult
     */
    private ProcessChainResult convertGraphToResult(ProcessChainGraph graph, Set<String> traceIds) {
        ProcessChainResult result = new ProcessChainResult();
        
        // 转换节点
        List<ChainBuilderNode> nodes = new ArrayList<>();
        for (GraphNode graphNode : graph.getAllNodes()) {
            ChainBuilderNode node = convertGraphNodeToBuilderNode(graphNode);
            nodes.add(node);
        }
        result.setNodes(nodes);
        
        // 转换边
        List<ChainBuilderEdge> edges = new ArrayList<>();
        for (String edgeKey : graph.getAllEdgeKeys()) {
            String[] parts = edgeKey.split("->");
            if (parts.length == 2) {
                ChainBuilderEdge edge = new ChainBuilderEdge();
                edge.setSource(parts[0]);
                edge.setTarget(parts[1]);
                
                EdgeInfo edgeInfo = graph.getEdgeInfo(edgeKey);
                if (edgeInfo != null) {
                    edge.setVal(edgeInfo.getLabel());
                }
                
                edges.add(edge);
            }
        }
        result.setEdges(edges);
        
        // 设置根节点和断链节点
        result.setRootNodes(graph.getRootNodes());
        result.setBrokenNodes(graph.getBrokenNodes());
        result.setTraceIdToRootNodeMap(graph.getTraceIdToRootNodeMap());
        result.setBrokenNodeToTraceId(graph.getBrokenNodeToTraceId());
        
        return result;
    }
    
    /**
     * 将GraphNode转换为ChainBuilderNode
     */
    private ChainBuilderNode convertGraphNodeToBuilderNode(GraphNode graphNode) {
        ChainBuilderNode node = new ChainBuilderNode();
        
        node.setProcessGuid(graphNode.getNodeId());
        node.setParentProcessGuid(graphNode.getParentProcessGuid());
        node.setTraceId(graphNode.getTraceId());
        node.setHostAddress(graphNode.getHostAddress());
        node.setIsRoot(graphNode.isRoot());
        node.setIsBroken(graphNode.isBroken());
        node.setIsAlarm(graphNode.isAlarm());
        node.setNodeType(graphNode.getNodeType());  // 传递节点类型
        
        // 复制告警和日志
        if (graphNode.getAlarms() != null) {
            for (RawAlarm alarm : graphNode.getAlarms()) {
                node.addAlarm(alarm);
            }
        }
        
        if (graphNode.getLogs() != null) {
            for (RawLog log : graphNode.getLogs()) {
                node.addLog(log);
            }
        }
        
        return node;
    }
    
    /**
     * 构建双向进程链(用于高危告警)
     */
    private void buildBidirectionalChain(RawAlarm alarm, ChainTraversalContext context) {
        if (alarm == null) {
            log.warn("【进程链生成】-> 告警为空,跳过双向遍历");
            return;
        }
        
        String processGuid = alarm.getProcessGuid();
        if (processGuid == null || processGuid.trim().isEmpty()) {
            log.warn("【进程链生成】-> 告警processGuid为空,跳过双向遍历: eventId={}", alarm.getEventId());
            return;
        }
        
        // 先添加告警对应的节点，包含很多重要数据
        addAlarmNode(alarm);
        
        // 检查告警节点本身是否是根节点
        if (context.getTraceIds().contains(processGuid)) {
            foundRootNode = true;
            rootNodes.add(processGuid);
            // ✅ 优化：设置节点的 isRoot 属性（用于 NodeIndex）
            ChainBuilderNode node = nodeMap.get(processGuid);
            if (node != null) {
                node.setIsRoot(true);
            }
            // 记录 traceId 到根节点的映射（告警的 traceId 就是 processGuid）
            traceIdToRootNodeMap.put(alarm.getTraceId(), processGuid);
            log.info("【进程链生成】-> 告警节点本身就是根节点: processGuid={} (匹配traceIds), 记录映射: traceId={} -> rootNodeId={}", 
                    processGuid, alarm.getTraceId(), processGuid);
        }
        
        // 添加告警对应的同级日志节点
        List<RawLog> sameLevelLogs = context.getLogsByProcessGuid().get(processGuid);
        if (sameLevelLogs != null) {
            for (RawLog rawLog : sameLevelLogs) {
                if (isValidLogType(rawLog.getLogType())) {
                    addLogNode(rawLog, true);
                    // 检查日志节点是否是根节点
                    String logProcessGuid = rawLog.getProcessGuid();
                    if (logProcessGuid != null && context.getTraceIds().contains(logProcessGuid)) {
                        foundRootNode = true;
                        rootNodes.add(logProcessGuid);
                        // ✅ 优化：设置节点的 isRoot 属性（用于 NodeIndex）
                        ChainBuilderNode logNode = nodeMap.get(logProcessGuid);
                        if (logNode != null) {
                            logNode.setIsRoot(true);
                        }
                        log.info("【进程链生成】-> 日志节点是根节点: processGuid={} (匹配traceIds)", logProcessGuid);
                    }
                }
            }
        }
        
        // 向上遍历（如果告警节点不是根节点）
        if (!context.getTraceIds().contains(processGuid)) {
            visitedNodesInPath.clear();
            // 如果该节点在本次任务中已经完整向上遍历过，则不再重复 DFS
            if (globalVisitedUp.contains(processGuid)) {
                log.debug("【进程链生成】-> 节点 {} 已完成向上遍历，本次跳过重复 DFS", processGuid);
            } else {
                traverseUpward(processGuid, context, 0);
            }
        }
        
        // 向下遍历
        visitedNodesInPath.clear();
        // 如果该节点在本次任务中已经完整向下遍历过，则不再重复 DFS
        if (globalVisitedDown.contains(processGuid)) {
            log.debug("【进程链生成】-> 节点 {} 已完成向下遍历，本次跳过重复 DFS", processGuid);
        } else {
            traverseDownward(processGuid, context, 0);
        }
    }
    
    /**
     * 构建向上进程链(用于中低危告警)
     */
    private void buildUpwardChain(RawAlarm alarm, ChainTraversalContext context) {
        if (alarm == null) {
            log.warn("【进程链生成】-> 告警为空,跳过向上遍历");
            return;
        }
        
        String processGuid = alarm.getProcessGuid();
        if (processGuid == null || processGuid.trim().isEmpty()) {
            log.warn("【进程链生成】-> 告警processGuid为空,跳过向上遍历: eventId={}", alarm.getEventId());
            return;
        }
        
        // 添加告警对应的节点
        addAlarmNode(alarm);
        
        // 检查告警节点本身是否是根节点
        if (context.getTraceIds().contains(processGuid)) {
            foundRootNode = true;
            rootNodes.add(processGuid);
            // ✅ 优化：设置节点的 isRoot 属性（用于 NodeIndex）
            ChainBuilderNode node = nodeMap.get(processGuid);
            if (node != null) {
                node.setIsRoot(true);
            }
            // 记录 traceId 到根节点的映射
            traceIdToRootNodeMap.put(alarm.getTraceId(), processGuid);
            log.info("【进程链生成】-> 告警节点本身就是根节点: processGuid={} (匹配traceIds), 记录映射: traceId={} -> rootNodeId={}", 
                    processGuid, alarm.getTraceId(), processGuid);
        }
        
        // 添加告警对应的同级日志节点
        List<RawLog> sameLevelLogs = context.getLogsByProcessGuid().get(processGuid);
        if (sameLevelLogs != null) {
            for (RawLog rawLog : sameLevelLogs) {
                if (isValidLogType(rawLog.getLogType())) {
                    addLogNode(rawLog, false);
                    // 检查日志节点是否是根节点
                    String logProcessGuid = rawLog.getProcessGuid();
                    if (logProcessGuid != null && context.getTraceIds().contains(logProcessGuid)) {
                        foundRootNode = true;
                        rootNodes.add(logProcessGuid);
                        // ✅ 优化：设置节点的 isRoot 属性（用于 NodeIndex）
                        ChainBuilderNode logNode = nodeMap.get(logProcessGuid);
                        if (logNode != null) {
                            logNode.setIsRoot(true);
                        }
                        log.info("【进程链生成】-> 日志节点是根节点: processGuid={} (匹配traceIds)", logProcessGuid);
                    }
                }
            }
        }
        
        // 向上遍历（如果告警节点不是根节点）
        if (!context.getTraceIds().contains(processGuid)) {
            visitedNodesInPath.clear();
            if (globalVisitedUp.contains(processGuid)) {
                log.debug("【进程链生成】-> 节点 {} 已完成向上遍历，本次跳过重复 DFS", processGuid);
            } else {
                traverseUpward(processGuid, context, 0);
            }
        }
    }
    
    /**
     * 向上递归遍历
     * 
     * @param depth 当前遍历深度
     */
    private void traverseUpward(String currentProcessGuid, 
                               ChainTraversalContext context,
                               int depth) {
        // 图级 visited：如果该节点在本次任务中已经向上遍历过，直接返回，避免重复 DFS
        if (globalVisitedUp.contains(currentProcessGuid)) {
            return;
        }
        
        // 检查深度限制
        if (depth >= MAX_TRAVERSE_DEPTH) {
            log.warn("【进程链生成】-> 向上遍历达到最大深度限制({}),停止遍历: {}", MAX_TRAVERSE_DEPTH, currentProcessGuid);
            // 达到深度上限后认为本节点已处理，避免后续重复尝试
            globalVisitedUp.add(currentProcessGuid);
            return;
        }
        
        // 检查是否已访问(检测环)
        if (visitedNodesInPath.contains(currentProcessGuid)) {
            log.warn("【进程链生成】-> 检测到环,停止遍历: {}", currentProcessGuid);
            // 检测到环后也认为本节点已处理，避免后续重复尝试
            globalVisitedUp.add(currentProcessGuid);
            return;
        }
        visitedNodesInPath.add(currentProcessGuid);
        
        // 查找当前节点
        ChainBuilderNode currentNode = nodeMap.get(currentProcessGuid);
        if (currentNode == null) {
            visitedNodesInPath.remove(currentProcessGuid);
            // 节点不存在，标记为已处理，避免后续重复尝试
            globalVisitedUp.add(currentProcessGuid);
            return;
        }
        
        // 检查当前节点是否是根节点（processGuid 匹配任意一个 traceId）
        // 终止条件1: 找到根节点
        if (context.getTraceIds().contains(currentProcessGuid)) {
            foundRootNode = true;
            rootNodes.add(currentProcessGuid);
            currentNode.setIsRoot(true);
            traceIdToRootNodeMap.put(currentProcessGuid, currentProcessGuid);
            log.info("【进程链生成】-> 找到根节点: processGuid={} (匹配traceIds), 记录映射: traceId={} -> rootNodeId={}", 
                    currentProcessGuid, currentProcessGuid, currentProcessGuid);
            visitedNodesInPath.remove(currentProcessGuid);
            globalVisitedUp.add(currentProcessGuid);
            return;
        }
        
        String parentProcessGuid = currentNode.getParentProcessGuid();

        // ✅ 关键修复：检查父节点是否存在（日志索引 或 告警索引）
        // 终止条件2: 父节点不存在（断链）
        if (parentProcessGuid == null || parentProcessGuid.isEmpty() ||
                !context.hasParentNode(parentProcessGuid)) {

            // 当前节点不是根节点，但父节点不存在 → 断链
            brokenNodes.add(currentProcessGuid);
            currentNode.setIsBroken(true);

            String nodeTraceId = extractTraceIdFromNode(currentNode);
            if (nodeTraceId != null && !nodeTraceId.isEmpty()) {
                brokenNodeToTraceId.put(currentProcessGuid, nodeTraceId);
                log.warn("【断链检测】-> 节点 {} (traceId={}) 的父节点 {} 不存在（日志和告警索引中均无），标记为断链节点",
                        currentProcessGuid, nodeTraceId,
                        parentProcessGuid != null ? parentProcessGuid : "null");
            } else {
                log.warn("【断链检测】-> 节点 {} 的父节点 {} 不存在（日志和告警索引中均无），标记为断链节点（未提取到traceId）",
                        currentProcessGuid,
                        parentProcessGuid != null ? parentProcessGuid : "null");
            }

            visitedNodesInPath.remove(currentProcessGuid);
            globalVisitedUp.add(currentProcessGuid);
            return;
        }
        
        // ✅ 父节点存在：优先从日志添加，否则从告警索引获取（纯告警场景）
        if (context.hasParentInLogs(parentProcessGuid)) {
            // 从日志索引获取父节点日志并添加
            List<RawLog> parentLogs = context.getParentLogs(parentProcessGuid);
            for (RawLog log : parentLogs) {
                if (isValidLogType(log.getLogType()) && 
                    parentProcessGuid.equals(log.getProcessGuid())) {
                    
                    addLogNode(log, false);
                    break;
                }
            }
        } else if (context.hasParentInAlarms(parentProcessGuid)) {
            // 从告警索引获取父节点（纯告警场景的关键修复）
            List<RawAlarm> parentAlarms = context.getParentAlarms(parentProcessGuid);
            if (parentAlarms != null && !parentAlarms.isEmpty()) {
                RawAlarm parentAlarm = parentAlarms.get(0);
                addAlarmNode(parentAlarm);
                log.debug("【进程链生成】-> 通过告警索引向上溯源: {} -> {}", 
                        parentProcessGuid, currentProcessGuid);
            }
        }
        // else: 父节点已在nodeMap中（可能在预处理或其他告警中已添加），无需重复添加
        
        // 添加边: 父节点 -> 当前节点
        addEdge(parentProcessGuid, currentProcessGuid);
        
        // 继续向上递归
        traverseUpward(parentProcessGuid, context, depth + 1);
        
        // 回溯时清理，允许其他路径访问该节点
        visitedNodesInPath.remove(currentProcessGuid);
        // 当前节点完整处理完毕，标记为已向上遍历
        globalVisitedUp.add(currentProcessGuid);
    }
    
    /**
     * 向下递归遍历
     * 
     * @param depth 当前遍历深度
     */
    private void traverseDownward(String currentProcessGuid,
                                  ChainTraversalContext context,
                                  int depth) {
        // 图级 visited：如果该节点在本次任务中已经向下遍历过，直接返回，避免重复 DFS
        if (globalVisitedDown.contains(currentProcessGuid)) {
            return;
        }
        
        // 检查深度限制
        if (depth >= MAX_TRAVERSE_DEPTH) {
            log.warn("向下遍历达到最大深度限制({}),停止遍历: {}", MAX_TRAVERSE_DEPTH, currentProcessGuid);
            globalVisitedDown.add(currentProcessGuid);
            return;
        }
        
        // 检查是否已访问(检测环)
        if (visitedNodesInPath.contains(currentProcessGuid)) {
            log.warn("检测到环,停止遍历: {}", currentProcessGuid);
            globalVisitedDown.add(currentProcessGuid);
            return;
        }
        visitedNodesInPath.add(currentProcessGuid);
        
        // ✅ 查找日志子节点和告警子节点
        List<RawLog> childLogs = context.getChildLogs(currentProcessGuid);
        List<RawAlarm> childAlarms = context.getChildAlarms(currentProcessGuid);
        
        // 如果既没有日志子节点也没有告警子节点，返回
        if ((childLogs == null || childLogs.isEmpty()) && 
            (childAlarms == null || childAlarms.isEmpty())) {
            visitedNodesInPath.remove(currentProcessGuid);
            globalVisitedDown.add(currentProcessGuid);
            return;
        }
        
        // 处理日志子节点
        if (childLogs != null && !childLogs.isEmpty()) {
            for (RawLog childLog : childLogs) {
                if (!isValidLogType(childLog.getLogType())) {
                    continue;
                }
                
                String childProcessGuid = childLog.getProcessGuid();
                if (childProcessGuid == null || childProcessGuid.isEmpty()) {
                    continue;
                }
                
                // 添加子节点
                addLogNode(childLog, false);
                
                // 添加同级节点
                List<RawLog> sameLevelLogs = context.getLogsByProcessGuid().get(childProcessGuid);
                if (sameLevelLogs != null) {
                    for (RawLog log : sameLevelLogs) {
                        if (isValidLogType(log.getLogType())) {
                            addLogNode(log, false);
                        }
                    }
                }
                
                // 添加边: 当前节点 -> 子节点
                addEdge(currentProcessGuid, childProcessGuid);
                
                // 继续向下递归
                traverseDownward(childProcessGuid, context, depth + 1);
            }
        }
        
        // ✅ 处理告警子节点（纯告警场景的关键修复）
        if (childAlarms != null && !childAlarms.isEmpty()) {
            for (RawAlarm childAlarm : childAlarms) {
                String childProcessGuid = childAlarm.getProcessGuid();
                if (childProcessGuid == null || childProcessGuid.isEmpty()) {
                    continue;
                }
                
                // 添加告警子节点
                addAlarmNode(childAlarm);
                
                // 添加边: 当前节点 -> 告警子节点
                addEdge(currentProcessGuid, childProcessGuid);
                
                log.debug("【进程链生成】-> 通过告警索引向下溯源: {} -> {}", 
                        currentProcessGuid, childProcessGuid);
                
                // 继续向下递归
                traverseDownward(childProcessGuid, context, depth + 1);
            }
        }
        
        visitedNodesInPath.remove(currentProcessGuid);
        // 当前节点完整处理完毕，标记为已向下遍历
        globalVisitedDown.add(currentProcessGuid);
    }
    
    /**
     * 使用智能策略裁剪节点
     * 
     * 智能裁剪策略：
     * 1. 强制保留：根节点、网端关联节点、高危/中危告警节点
     * 2. 级联保留：从关键节点到根节点的完整路径
     * 3. 选择性保留：如果还有剩余槽位，按分数选择其他节点
     * 4. 优势：关键攻击路径完整，无需 Explore 节点
     * 
     * 使用 ProcessChainPruner 工具类实现
     */
    private void pruneNodesWithSmartStrategy() {
        try {
            // 创建裁剪上下文
            PruneContext context = new PruneContext(
                nodeMap,
                edges,
                rootNodes,
                associatedEventIds
            );
            
            // 执行智能裁剪
            PruneResult result = ProcessChainPruner.pruneNodes(context);
            
            // 记录裁剪结果
            log.info("【进程链生成】-> 智能裁剪完成: 原始节点={}, 必须保留={}, 级联保留={}, 移除节点={}, 最终节点={}",
                     result.getOriginalNodeCount(),
                     result.getMustKeepCount(),
                     result.getCascadeKeepCount(),
                     result.getRemovedNodeCount(),
                     result.getFinalNodeCount());
            
        } catch (Exception e) {
            log.error("【进程链生成】-> 智能裁剪异常: {}", e.getMessage(), e);
            throw e;
        }
    }
    
    /**
     * 添加告警节点
     */
    private void addAlarmNode(RawAlarm alarm) {
        String processGuid = alarm.getProcessGuid();
        if (processGuid == null || processGuid.isEmpty()) {
            return;
        }
        ChainBuilderNode node = nodeMap.get(processGuid);
        if (node == null) {
            node = new ChainBuilderNode();
            node.setProcessGuid(processGuid);
            node.setParentProcessGuid(alarm.getParentProcessGuid());
            node.setIsAlarm(true);
            nodeMap.put(processGuid, node);
        }
        
        // 添加告警信息，在build中
        node.addAlarm(alarm);
    }
    
    /**
     * 添加日志节点
     */
    private void addLogNode(RawLog log, boolean isFromAlarm) {
        String processGuid = log.getProcessGuid();
        if (processGuid == null || processGuid.isEmpty()) {
            return;
        }
        
        ChainBuilderNode node = nodeMap.get(processGuid);
        if (node == null) {
            node = new ChainBuilderNode();
            node.setProcessGuid(processGuid);
            node.setParentProcessGuid(log.getParentProcessGuid());
            nodeMap.put(processGuid, node);
        }
        
        // 添加日志信息
        node.addLog(log);
    }
    
    /**
     * 添加边
     */
    private void addEdge(String source, String target) {
        // 检查参数有效性
        if (source == null || source.isEmpty() || target == null || target.isEmpty()) {
            log.warn("【边添加】-> 跳过无效边：source={}, target={}", source, target);
            return;
        }
        
        // ✅ 防止自环：source 不能等于 target
        if (source.equals(target)) {
            // 仅对同一个 source 记录一次 WARN，避免日志刷屏
            if (!selfLoopWarned.contains(source)) {
                log.warn("【边添加】-> 检测到自环，跳过添加：source=target={}", source);
                selfLoopWarned.add(source);
            } else {
                log.debug("【边添加】-> 自环重复出现，已跳过：source=target={}", source);
            }
            return;
        }
        
        // 使用 edgeKeySet 快速判断边是否已存在，避免 O(E) 遍历
        String key = source + "->" + target;
        if (edgeKeySet.contains(key)) {
            return;
        }
        
        ChainBuilderEdge edge = new ChainBuilderEdge();
        edge.setSource(source);
        edge.setTarget(target);
        edges.add(edge);
        edgeKeySet.add(key);
    }
    
    /**
     * 根据目标节点的 logType 和 opType 设置边的 val 值
     * 
     * 规则：
     * - 如果边的 val 不是默认值"连接"（如桥接边、扩展边的特殊值），则不覆盖
     * - logType=file 且 opType=delete：val = ""（空字符串）
     * - 其他情况：保持默认值 "连接"（由 ProcessEdge 构造函数设置）
     * 
     * @param edge 要设置的边
     * @param targetNodeId 目标节点ID
     * @param nodes 已转换的节点列表
     */
    private void setEdgeValByTargetNode(
            com.security.processchain.model.ProcessEdge edge,
            String targetNodeId,
            List<com.security.processchain.model.ProcessNode> nodes) {
        
        // 如果边的 val 不是默认值"连接"（如桥接边"桥接"、扩展边""等特殊值），则不覆盖
        String currentVal = edge.getVal();
        if (currentVal != null && !"连接".equals(currentVal)) {
            return;  // 保护特殊边（桥接、扩展等）不被覆盖
        }
        
        // 查找目标节点
        com.security.processchain.model.ProcessNode targetNode = null;
        for (com.security.processchain.model.ProcessNode node : nodes) {
            if (node != null && targetNodeId.equals(node.getNodeId())) {
                targetNode = node;
                break;
            }
        }
        
        if (targetNode == null) {
            return;  // 节点不存在，保持默认值 "连接"
        }
        
        String logType = targetNode.getLogType();
        String opType = targetNode.getOpType();
        
        // 特殊规则：文件删除操作，边的 val 为空字符串
        if ("file".equalsIgnoreCase(logType) && "delete".equalsIgnoreCase(opType)) {
            edge.setVal("");
        }
        // 其他情况保持默认值 "连接"（已由 ProcessEdge 构造函数设置）
    }
    
    /**
     * 将日志按processGuid索引
     */
    private Map<String, List<RawLog>> indexLogsByProcessGuid(List<RawLog> logs) {
        Map<String, List<RawLog>> index = new HashMap<>();
        if (logs == null) {
            return index;
        }
        
        for (RawLog log : logs) {
            String processGuid = log.getProcessGuid();
            if (processGuid != null && !processGuid.isEmpty()) {
                index.computeIfAbsent(processGuid, k -> new ArrayList<>()).add(log);
            }
        }
        return index;
    }
    
    /**
     * 将日志按parentProcessGuid索引
     */
    private Map<String, List<RawLog>> indexLogsByParentProcessGuid(List<RawLog> logs) {
        Map<String, List<RawLog>> index = new HashMap<>();
        if (logs == null) {
            return index;
        }
        
        for (RawLog log : logs) {
            String parentProcessGuid = log.getParentProcessGuid();
            if (parentProcessGuid != null && !parentProcessGuid.isEmpty()) {
                index.computeIfAbsent(parentProcessGuid, k -> new ArrayList<>()).add(log);
            }
        }
        return index;
    }
    
    /**
     * 将告警按processGuid索引
     */
    private Map<String, List<RawAlarm>> indexAlarmsByProcessGuid(List<RawAlarm> alarms) {
        Map<String, List<RawAlarm>> index = new HashMap<>();
        if (alarms == null) {
            return index;
        }
        
        for (RawAlarm alarm : alarms) {
            String processGuid = alarm.getProcessGuid();
            if (processGuid != null && !processGuid.isEmpty()) {
                index.computeIfAbsent(processGuid, k -> new ArrayList<>()).add(alarm);
            }
        }
        return index;
    }
    
    /**
     * 将告警按parentProcessGuid索引
     */
    private Map<String, List<RawAlarm>> indexAlarmsByParentProcessGuid(List<RawAlarm> alarms) {
        Map<String, List<RawAlarm>> index = new HashMap<>();
        if (alarms == null) {
            return index;
        }
        
        for (RawAlarm alarm : alarms) {
            String parentProcessGuid = alarm.getParentProcessGuid();
            if (parentProcessGuid != null && !parentProcessGuid.isEmpty()) {
                index.computeIfAbsent(parentProcessGuid, k -> new ArrayList<>()).add(alarm);
            }
        }
        return index;
    }
    
    /**
     * 判断是否是高危
     */
    private boolean isHighSeverity(String severity) {
        return "HIGH".equalsIgnoreCase(severity) || "高".equals(severity);
    }
    
    /**
     * 判断是否是中危
     */
    private boolean isMediumSeverity(String severity) {
        return "MEDIUM".equalsIgnoreCase(severity) || "中".equals(severity);
    }
    
    /**
     * 从节点中提取 traceId
     * 优先从告警中获取，其次从日志中获取
     */
    private String extractTraceIdFromNode(ChainBuilderNode node) {
        if (node == null) {
            return null;
        }
        
        // 1. 优先从告警中获取 traceId
        if (node.getAlarms() != null && !node.getAlarms().isEmpty()) {
            for (RawAlarm alarm : node.getAlarms()) {
                if (alarm != null && alarm.getTraceId() != null && !alarm.getTraceId().isEmpty()) {
                    return alarm.getTraceId();
                }
            }
        }
        
        // 2. 从日志中获取 traceId
        if (node.getLogs() != null && !node.getLogs().isEmpty()) {
            for (RawLog log : node.getLogs()) {
                if (log != null && log.getTraceId() != null && !log.getTraceId().isEmpty()) {
                    return log.getTraceId();
                }
            }
        }
        
        return null;
    }
    
    /**
     * 判断logType是否有效
     */
    private boolean isValidLogType(String logType) {
        if (logType == null) {
            return false;
        }
        for (String validType : ProcessChainConstants.LogType.BUILDER_LOG_TYPES) {
            if (validType.equalsIgnoreCase(logType)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 为断链节点添加 Explore 虚拟根节点
     * 
     * 策略（优化后）：
     * 1. 如果没有断链节点，检查是否有 traceId 没有真实根节点
     * 2. 为每个没有真实根节点的 traceId 创建独立的 EXPLORE 节点
     *    - 节点ID格式：EXPLORE_ROOT_{traceId}
     *    - 每个 traceId 有自己独立的虚拟根节点
     *    - 支持多个 victim 连接到不同的 EXPLORE 节点
     * 3. 将断链节点连接到对应 traceId 的 EXPLORE 节点
     * 
     * @param finalNodes 最终节点列表
     * @param finalEdges 最终边列表
     * @param brokenNodes 断链节点集合
     * @param rootNodes 真实根节点集合
     * @param traceIds 所有 traceId 集合
     * @param traceIdToRootNodeMap traceId 到根节点的映射（会被修改）
     */
    private void addExploreNodesForBrokenChains(
            List<com.security.processchain.model.ProcessNode> finalNodes,
            List<com.security.processchain.model.ProcessEdge> finalEdges,
            Set<String> brokenNodes,
            Set<String> rootNodes,
            Set<String> traceIds,
            Map<String, String> traceIdToRootNodeMap,
            Map<String, String> brokenNodeToTraceId) {
        
        if (traceIds == null || traceIds.isEmpty()) {
            log.warn("【进程链生成】-> traceIds为空，无法创建 Explore 节点");
            return;
        }
        
        // 第1步：找出所有没有真实根节点的 traceId
        Set<String> traceIdsWithoutRoot = new HashSet<>();
        for (String traceId : traceIds) {
            if (!traceIdToRootNodeMap.containsKey(traceId)) {
                traceIdsWithoutRoot.add(traceId);
            }
        }
        
        // 第2步：如果所有 traceId 都有真实根节点，且没有断链，则不需要 Explore
        if (traceIdsWithoutRoot.isEmpty() && (brokenNodes == null || brokenNodes.isEmpty())) {
            log.info("【进程链生成】-> 所有 traceId 都有真实根节点，且无断链，不需要添加 Explore");
            return;
        }
        
        log.info("【进程链生成】-> 开始为 {} 个没有真实根节点的 traceId 创建独立的 Explore 节点", 
                traceIdsWithoutRoot.size());
        
        // 第3步：为每个没有真实根节点的 traceId 创建独立的 EXPLORE 节点
        int exploreNodeCount = 0;
        for (String traceId : traceIdsWithoutRoot) {
            // 创建独立的 EXPLORE 节点ID
            String exploreNodeId = "EXPLORE_ROOT_" + traceId;
            
            com.security.processchain.model.ProcessNode exploreNode = 
                    new com.security.processchain.model.ProcessNode();
            exploreNode.setNodeId(exploreNodeId);
            exploreNode.setIsChainNode(true);
            exploreNode.setLogType("explore");
            
            ChainNode exploreChainNode = new ChainNode();
            exploreChainNode.setIsRoot(true);   // 虚拟根节点
            exploreChainNode.setIsBroken(false);
            exploreChainNode.setIsAlarm(false);
            
            exploreNode.setChainNode(exploreChainNode);
            exploreNode.setStoryNode(null);
            
            // 添加 Explore 节点到列表
            finalNodes.add(exploreNode);
            exploreNodeCount++;
            
            // 记录 traceId 到 EXPLORE 节点的映射
            traceIdToRootNodeMap.put(traceId, exploreNodeId);
            
            log.info("【进程链生成】-> 创建独立 Explore 节点: traceId={} -> nodeId={}", 
                    traceId, exploreNodeId);
        }
        
        // 第4步：将断链节点连接到对应的 EXPLORE（上面创建） 节点
        // 使用 brokenNodeToTraceId 映射来确定每个断链节点属于哪个 traceId
        if (brokenNodes != null && !brokenNodes.isEmpty()) {
            int connectedCount = 0;
            int unmappedCount = 0;
            
            for (String brokenNodeGuid : brokenNodes) {
                // 查找断链节点的 traceId
                String nodeTraceId = brokenNodeToTraceId.get(brokenNodeGuid);
                
                if (nodeTraceId != null && traceIdToRootNodeMap.containsKey(nodeTraceId)) {
                    // 找到了对应的 EXPLORE 节点
                    String exploreNodeId = traceIdToRootNodeMap.get(nodeTraceId);
                    
                    com.security.processchain.model.ProcessEdge exploreEdge = 
                            new com.security.processchain.model.ProcessEdge();
                    exploreEdge.setSource(exploreNodeId);
                    exploreEdge.setTarget(brokenNodeGuid);
                    exploreEdge.setVal("断链");
                    
                    finalEdges.add(exploreEdge);
                    connectedCount++;
                    
                    log.debug("【进程链生成】-> 连接断链节点 {} (traceId={}) 到虚拟根节点 {}", 
                            brokenNodeGuid, nodeTraceId, exploreNodeId);
                } else {
                    // 未找到 traceId 映射，尝试连接到第一个 EXPLORE
                    if (!traceIdsWithoutRoot.isEmpty()) {
                        String firstTraceId = traceIdsWithoutRoot.iterator().next();
                        String exploreNodeId = traceIdToRootNodeMap.get(firstTraceId);
                        
                        com.security.processchain.model.ProcessEdge exploreEdge = 
                                new com.security.processchain.model.ProcessEdge();
                        exploreEdge.setSource(exploreNodeId);
                        exploreEdge.setTarget(brokenNodeGuid);
                        exploreEdge.setVal("断链");
                        
                        finalEdges.add(exploreEdge);
                        unmappedCount++;
                        
                        log.warn("【进程链生成】-> 断链节点 {} 未找到traceId映射，连接到第一个 Explore 节点: {}", 
                                brokenNodeGuid, exploreNodeId);
                    }
                }
            }
            
            log.info("【进程链生成】-> 断链节点连接完成: 成功匹配={}, 未匹配={}, 总数={}", 
                    connectedCount, unmappedCount, brokenNodes.size());
        }
        
        log.info("【进程链生成】-> Explore 节点创建完成: 共创建 {} 个独立的虚拟根节点", exploreNodeCount);
        log.info("【进程链生成】-> traceId到根节点映射更新: {}", traceIdToRootNodeMap);
    }
    

    /**
     * 直接构建最终的 IncidentProcessChain（一步到位）
     * 支持多个 traceId 和多个 associatedEventId
     * 
     * @param alarms 告警列表
     * @param logs 日志列表
     * @param traceIds 追踪 ID 集合
     * @param associatedEventIds 关联事件 ID 集合
     * @param startLogEventIds 无告警场景的起点日志eventId集合(可为null)
     * @param nodeMapper 节点映射器
     * @param edgeMapper 边映射器
     * @return 完整的 IncidentProcessChain
     */
    public IncidentProcessChain buildIncidentChain(
            List<RawAlarm> alarms, 
            List<RawLog> logs,
            Set<String> traceIds,
            Set<String> associatedEventIds,
            Set<String> startLogEventIds,
            NodeMapper nodeMapper, 
            EdgeMapper edgeMapper) {
        
        // 允许无告警场景（只要有日志和startLogEventIds）
        if ((alarms == null || alarms.isEmpty()) && 
            (startLogEventIds == null || startLogEventIds.isEmpty())) {
            log.warn("【进程链生成】-> 警告: 告警和起点日志都为空，返回空进程链");
            return new IncidentProcessChain();
        }
        
        if (traceIds == null || traceIds.isEmpty()) {
            log.error("【进程链生成】-> 错误: traceIds为空，无法构建进程链");
            return new IncidentProcessChain();
        }
        
        try {
            log.info("【进程链生成】-> 开始构建进程链: traceIds={}, 关联事件数={}, 起点日志数={}, 告警数={}, 日志数={}", 
                    traceIds, 
                    (associatedEventIds != null ? associatedEventIds.size() : 0),
                    (startLogEventIds != null ? startLogEventIds.size() : 0),
                    alarms.size(), 
                    (logs != null ? logs.size() : 0));
            
            // 构建内部结果
            ProcessChainResult result = buildProcessChain(alarms, logs, traceIds, associatedEventIds, startLogEventIds);
            
            // ✅ 同步 traceIdToRootNodeMap（确保在没有断链节点时也能获取）
            // buildProcessChain 内部已经同步过，这里再次确认
            if (this.traceIdToRootNodeMap == null || this.traceIdToRootNodeMap.isEmpty()) {
                this.traceIdToRootNodeMap = result.getTraceIdToRootNodeMap();
                log.info("【进程链生成】-> 从 result 同步 traceIdToRootNodeMap: {}", this.traceIdToRootNodeMap);
            }
            
            // 转换为最终的 IncidentProcessChain
            IncidentProcessChain incidentChain = new IncidentProcessChain();
            
            List<com.security.processchain.model.ProcessNode> finalNodes = new ArrayList<>();
            List<com.security.processchain.model.ProcessEdge> finalEdges = new ArrayList<>();
            
            // 转换节点，映射到输出接哦构体中，并添加实体等内容
            if (result.getNodes() != null) {
                for (ChainBuilderNode builderNode : result.getNodes()) {
                    com.security.processchain.model.ProcessNode finalNode = nodeMapper.toIncidentNode(builderNode);
                    
                    // 设置 isRoot 和 isBroken 标志
                    if (finalNode != null && finalNode.getIsChainNode() && finalNode.getChainNode() != null) {
                        String nodeId = finalNode.getNodeId();
                        if (result.getRootNodes() != null && result.getRootNodes().contains(nodeId)) {
                            finalNode.getChainNode().setIsRoot(true);
                        }
                        if (result.getBrokenNodes() != null && result.getBrokenNodes().contains(nodeId)) {
                            finalNode.getChainNode().setIsBroken(true);
                        }
                    }
                    
                    finalNodes.add(finalNode);
                }
            }
            
            // 转换边，映射到输出结构中
            if (result.getEdges() != null) {
                for (ChainBuilderEdge builderEdge : result.getEdges()) {
                    com.security.processchain.model.ProcessEdge finalEdge = edgeMapper.toIncidentEdge(builderEdge);
                    
                    // 根据目标节点设置边的 val 值
                    setEdgeValByTargetNode(finalEdge, builderEdge.getTarget(), finalNodes);
                    
                    finalEdges.add(finalEdge);
                }
            }
            
            // 添加 Explore 节点（如果有断链）
            if (result.getBrokenNodes() != null && !result.getBrokenNodes().isEmpty()) {
                addExploreNodesForBrokenChains(finalNodes, finalEdges, 
                        result.getBrokenNodes(), result.getRootNodes(), 
                        traceIds, result.getTraceIdToRootNodeMap(), 
                        result.getBrokenNodeToTraceId());
                
                // ✅ 关键修复：将更新后的映射同步回 ProcessChainBuilder 的成员变量
                // 因为 addExploreNodesForBrokenChains() 会更新 result 中的 traceIdToRootNodeMap
                this.traceIdToRootNodeMap = result.getTraceIdToRootNodeMap();
                this.brokenNodeToTraceId = result.getBrokenNodeToTraceId();
                
                log.info("【进程链生成】-> Explore节点添加后，映射更新: traceIdToRootNodeMap={}", 
                        this.traceIdToRootNodeMap);
            }
            
            incidentChain.setNodes(finalNodes);
            incidentChain.setEdges(finalEdges);
            
            // ✅ 优化：不再将 traceIdToRootNodeMap 设置到 IncidentProcessChain
            // traceIdToRootNodeMap 通过 getTraceIdToRootNodeMap() 方法单独获取
            // 作为方法参数传递，而不是作为业务数据模型的一部分
            
            log.info("【进程链生成】-> IncidentProcessChain 构建完成: 节点数={}, 边数={}", 
                    finalNodes.size(), finalEdges.size());
            
            return incidentChain;
            
        } catch (Exception e) {
            log.error("【进程链生成】-> 构建 IncidentProcessChain 失败: {}", e.getMessage(), e);
            return new IncidentProcessChain();
        }
    }
}
