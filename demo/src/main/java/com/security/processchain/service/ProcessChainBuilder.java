package com.security.processchain.service;

import com.security.processchain.constants.ProcessChainConstants;
import com.security.processchain.model.ProcessEdge;
import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.util.*;
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
            
            // 2.1 有告警场景：根据是否有网端关联选择起点
            if (alarms != null && !alarms.isEmpty()) {
                // 情况1：有网端关联 → 以关联的告警为起点，但需确保每个 traceId 都有起点
                if (associatedEventIds != null && !associatedEventIds.isEmpty()) {
                    int matchedCount = 0;
                    Set<String> coveredTraceIds = new HashSet<>();
                    
                    // 步骤1：添加网端关联的告警作为起点
                    for (RawAlarm alarm : alarms) {
                        if (alarm != null && alarm.getEventId() != null && 
                            associatedEventIds.contains(alarm.getEventId())) {
                            if (alarm.getProcessGuid() != null) {
                                startNodes.add(alarm.getProcessGuid());
                                matchedCount++;
                                if (alarm.getTraceId() != null) {
                                    coveredTraceIds.add(alarm.getTraceId());
                                }
                                log.debug("【网端关联】匹配告警: eventId={}, processGuid={}, traceId={}", 
                                        alarm.getEventId(), alarm.getProcessGuid(), alarm.getTraceId());
                            }
                        }
                    }
                    
                    log.info("【网端关联场景】使用关联告警作为起点: 关联eventId数={}, 匹配告警数={}, 起点节点数={}, 覆盖traceId数={}", 
                            associatedEventIds.size(), matchedCount, startNodes.size(), coveredTraceIds.size());
                    
                    // 步骤2：✅ 关键修复 - 为未覆盖的 traceId 补充起点-- 有些traceid不是网端关联场景
                    if (traceIds != null && !traceIds.isEmpty()) {
                        Set<String> uncoveredTraceIds = new HashSet<>(traceIds);
                        uncoveredTraceIds.removeAll(coveredTraceIds);
                        
                        if (!uncoveredTraceIds.isEmpty()) {
                            log.warn("【网端关联场景】发现未覆盖的 traceId: {} / {}", 
                                    uncoveredTraceIds.size(), traceIds.size());
                            log.warn("【网端关联场景】未覆盖的 traceId 列表: {}", uncoveredTraceIds);
                            
                            int supplementCount = 0;
                            // 为每个未覆盖的 traceId 找一个告警作为起点
                            for (String uncoveredTraceId : uncoveredTraceIds) {
                                for (RawAlarm alarm : alarms) {
                                    if (alarm != null && 
                                        uncoveredTraceId.equals(alarm.getTraceId()) && 
                                        alarm.getProcessGuid() != null) {
                                        
                                        startNodes.add(alarm.getProcessGuid());
                                        coveredTraceIds.add(uncoveredTraceId);
                                        supplementCount++;
                                        
                                        log.info("【起点补充】为未关联的 traceId [{}] 添加起点: processGuid={}, eventId={}", 
                                                uncoveredTraceId, alarm.getProcessGuid(), alarm.getEventId());
                                        break;  // 每个 traceId 只需要一个起点
                                    }
                                }
                            }
                            
                            log.info("【起点补充】补充了 {} 个未覆盖 traceId 的起点，最终覆盖 traceId 数: {} / {}", 
                                    supplementCount, coveredTraceIds.size(), traceIds.size());
                        } else {
                            log.info("【网端关联场景】✅ 所有 traceId 都已覆盖");
                        }
                    }
                    
                    if (startNodes.isEmpty()) {
                        log.warn("【网端关联】未找到任何匹配的关联告警，关联eventIds: {}", associatedEventIds);
                    }
                }
                // 情况2：无网端关联 → 以所有告警为起点
                else {
                    for (RawAlarm alarm : alarms) {
                        if (alarm != null && alarm.getProcessGuid() != null) {
                            startNodes.add(alarm.getProcessGuid());
                        }
                    }
                    log.info("【普通告警场景】使用所有告警作为起点: {}", startNodes.size());
                }
            }
            // 2.2 无告警场景：使用指定日志的processGuid作为起点
            else if (startLogEventIds != null && !startLogEventIds.isEmpty()) {
                log.info("【无告警场景】开始处理起点日志: startLogEventIds={}", startLogEventIds);
                log.info("【无告警场景】日志总数={}", logs != null ? logs.size() : 0);
                
                // 根据eventId找到对应的日志，获取其processGuid
                Map<String, String> eventIdToProcessGuid = new HashMap<>();
                
                if (logs == null || logs.isEmpty()) {
                    log.error("【无告警场景】❌ 日志列表为空，无法找到起点日志！");
                } else {
                    int matchedCount = 0;
                    for (RawLog rawLog : logs) {
                        if (rawLog == null) continue;
                        
                        String logEventId = rawLog.getEventId();
                        if (logEventId != null && startLogEventIds.contains(logEventId)) {
                            eventIdToProcessGuid.put(logEventId, rawLog.getProcessGuid());
                            matchedCount++;
                            log.info("【无告警场景】✅ 找到匹配日志: eventId={}, processGuid={}", 
                                    logEventId, rawLog.getProcessGuid());
                        }
                    }
                    log.info("【无告警场景】匹配的日志数: {}/{}", matchedCount, startLogEventIds.size());
                }
                
                // 在图中找到对应的节点
                for (String eventId : startLogEventIds) {
                    String processGuid = eventIdToProcessGuid.get(eventId);
                    
                    if (processGuid == null) {
                        log.warn("【无告警场景】❌ eventId [{}] 在日志中找不到对应的processGuid", eventId);
                        continue;
                    }
                    
                    if (!fullGraph.hasNode(processGuid)) {
                        log.warn("【无告警场景】❌ processGuid [{}] 在图中不存在 (eventId={})", 
                                processGuid, eventId);
                        log.warn("【无告警场景】图中现有节点数: {}", fullGraph.getNodeCount());
                        continue;
                    }
                    
                    startNodes.add(processGuid);
                    log.info("【无告警场景】✅ 添加起点节点: eventId={}, processGuid={}", 
                            eventId, processGuid);
                }
                
                if (startNodes.isEmpty()) {
                    log.error("【无告警场景】❌ 没有找到任何有效的起点节点！");
                    log.error("  - 提供的eventIds: {}", startLogEventIds);
                    log.error("  - 匹配到的processGuids: {}", eventIdToProcessGuid.keySet());
                    log.error("  - 图中节点数: {}", fullGraph.getNodeCount());
                }
                
                log.info("【无告警场景】使用指定日志作为起点: eventIds={}, 节点数={}", 
                        startLogEventIds, startNodes.size());
            }
            // 2.3 无告警无网段端关联日志场景：后续统一兜底处理
            
            log.info("【起点节点】当前收集到 {} 个起点", startNodes.size());
            
            // ✅ 统一兜底：如果 startNodes 为空，使用根节点
            if (startNodes.isEmpty()) {
                log.warn("【兜底检查】未找到有效的起点节点，开始兜底处理...");
                log.warn("  - 告警数量: {}", alarms != null ? alarms.size() : 0);
                log.warn("  - 日志数量: {}", logs != null ? logs.size() : 0);
                log.warn("  - 关联告警eventIds数量: {}", associatedEventIds != null ? associatedEventIds.size() : 0);
                log.warn("  - 起点日志eventIds数量: {}", startLogEventIds != null ? startLogEventIds.size() : 0);
                log.warn("  - 图节点总数: {}", fullGraph.getNodeCount());
                log.warn("  - 根节点数: {}", fullGraph.getRootNodes().size());
                
                // 兜底方案：使用根节点
                if (!fullGraph.getRootNodes().isEmpty()) {
                    startNodes.addAll(fullGraph.getRootNodes());
                    log.info("【兜底方案】✅ 使用 {} 个根节点作为起点", startNodes.size());
                } else {
                    log.error("【致命错误】❌ 图中没有根节点，无法生成进程链！");
                    return new ProcessChainResult();  // 返回空结果
                }
            }
            
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
            
            log.info("【子图提取完成】进程节点数={}", subgraph.getNodeCount());
            
            // ===== 阶段4.5：父进程拆分（延迟创建虚拟父节点）✅ 新增 =====
            log.info("【父进程拆分】开始为子图节点创建虚拟父节点...");
            createVirtualParentsForSubgraph(subgraph, traceIds);
            log.info("【父进程拆分完成】子图节点总数={}", subgraph.getNodeCount());
            
            // ===== 阶段4.6：图分析（完整）✅ 新增 =====
            log.info("【图分析】开始识别根节点和断链节点...");
            subgraph.identifyRootNodes(traceIds != null ? traceIds : Collections.emptySet());
            log.info("【图分析完成】");
            
            // ===== 阶段4.7：调整虚拟父节点的 parentProcessGuid ✅ 新增 =====
            log.info("【虚拟父节点调整】开始调整虚拟父节点的 parentProcessGuid...");
            adjustVirtualParentLinks(subgraph);
            log.info("【虚拟父节点调整完成】");
            
            // ===== 阶段5：裁剪（如果需要）=====
            // 注意：此时只有进程节点，裁剪更高效
            if (subgraph.getNodeCount() > MAX_NODE_COUNT) {
                log.warn("【智能裁剪】进程节点数({})超过限制({}), 开始裁剪...", 
                        subgraph.getNodeCount(), MAX_NODE_COUNT);
                pruneGraph(subgraph);
                log.info("【智能裁剪完成】裁剪后进程节点数={}", subgraph.getNodeCount());
            }
            
            // ===== 阶段6：实体提取（晚拆分） =====
            // 在裁剪后的进程链上提取实体节点，避免实体节点断链
            EntityExtractor.extractEntitiesFromGraph(subgraph);
            
            log.info("【实体提取完成】节点总数={}", subgraph.getNodeCount());
            
            // ===== 阶段7：实体过滤 =====
            EntityFilterUtil.filterEntityNodesInGraph(subgraph);
            
            log.info("【实体过滤完成】最终节点数={}", subgraph.getNodeCount());
            
            // ===== 阶段8：转换为输出格式 =====
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
            
            // ⚠️ 调试：输出映射详情
            if (this.traceIdToRootNodeMap.isEmpty()) {
                log.warn("【映射检查】⚠️ traceIdToRootNodeMap 为空！");
                log.warn("  - 图中的映射: {}", subgraph.getTraceIdToRootNodeMap());
                log.warn("  - result中的映射: {}", result.getTraceIdToRootNodeMap());
                log.warn("  - 根节点列表: {}", this.rootNodes);
            } else {
                log.info("【映射检查】✅ traceIdToRootNodeMap: {}", this.traceIdToRootNodeMap);
            }
            
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
            
            // 转换边（直接从邻接表获取）
            for (GraphNode graphNode : graph.getAllNodes()) {
                String source = graphNode.getNodeId();
                List<String> children = graph.getChildren(source);
                for (String target : children) {
                    ChainBuilderEdge edge = new ChainBuilderEdge();
                    edge.setSource(source);
                    edge.setTarget(target);
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
            
            // 移除被裁剪的节点和边
            for (String nodeId : nodesToRemove) {
                graph.removeCutNode(nodeId);
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
        
        // 转换边（直接从邻接表获取，并获取边的值）
        List<ChainBuilderEdge> edges = new ArrayList<>();
        Map<String, String> edgeVals = graph.getEdgeVals();  // 获取所有边的值
        
        for (GraphNode graphNode : graph.getAllNodes()) {
            String source = graphNode.getNodeId();
            List<String> children = graph.getChildren(source);
            for (String target : children) {
                ChainBuilderEdge edge = new ChainBuilderEdge();
                edge.setSource(source);
                edge.setTarget(target);
                
                // ✅ 设置边的值（如"断链"）
                String edgeKey = source + "->" + target;
                String val = edgeVals.get(edgeKey);
                edge.setVal(val);
                
                if (val != null && !val.isEmpty()) {
                    log.debug("【边转换】设置边的值: {} → {}, val={}", 
                            source, target, val);
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
        node.setIsVirtual(graphNode.isVirtual());   // 传递虚拟节点标识
        
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
                log.info("【边添加】-> 自环重复出现，已跳过：source=target={}", source);
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
            ProcessEdge edge,
            String targetNodeId,
            List<ProcessNode> nodes) {
        
        // 如果边的 val 不是默认值"连接"（如桥接边"桥接"、扩展边""等特殊值），则不覆盖
        String currentVal = edge.getVal();
        if (currentVal != null && !"连接".equals(currentVal)) {
            return;  // 保护特殊边（桥接、扩展等）不被覆盖
        }
        
        // 查找目标节点
        ProcessNode targetNode = null;
        for (ProcessNode node : nodes) {
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
            List<ProcessNode> finalNodes,
            List<ProcessEdge> finalEdges,
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
            
            ProcessNode exploreNode = 
                    new ProcessNode();
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
                    
                    ProcessEdge exploreEdge = 
                            new ProcessEdge();
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
                        
                        ProcessEdge exploreEdge = 
                                new ProcessEdge();
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
     * @return 完整的 IncidentProcessChain
     */
    public IncidentProcessChain buildIncidentChain(
            List<RawAlarm> alarms, 
            List<RawLog> logs,
            Set<String> traceIds,
            Set<String> associatedEventIds,
            Set<String> startLogEventIds,
            NodeMapper nodeMapper) {
        
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
            
            // buildProcessChain 内部已经同步过，这里再次确认
            if (this.traceIdToRootNodeMap == null || this.traceIdToRootNodeMap.isEmpty()) {
                this.traceIdToRootNodeMap = result.getTraceIdToRootNodeMap();
                log.info("【进程链生成】-> 从 result 同步 traceIdToRootNodeMap: {}", this.traceIdToRootNodeMap);
            }

            // 转换为最终的 IncidentProcessChain
            IncidentProcessChain incidentChain = new IncidentProcessChain();
            
            List<ProcessNode> finalNodes = new ArrayList<>();
            List<ProcessEdge> finalEdges = new ArrayList<>();
            
            // 转换节点，映射到输出接结构体中，并添加实体等内容等，子图的内容都已经映射
            if (result.getNodes() != null) {
                for (ChainBuilderNode builderNode : result.getNodes()) {
                    ProcessNode finalNode = nodeMapper.toIncidentNode(builderNode);
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
                    // ✅ 直接创建 ProcessEdge，不再需要 EdgeMapper
                    ProcessEdge finalEdge = new ProcessEdge();
                    finalEdge.setSource(builderEdge.getSource());
                    finalEdge.setTarget(builderEdge.getTarget());
                    // val 默认为 "连接"（由 ProcessEdge 构造函数设置）
                    // 优先使用边的值（如"断链"）
                    if (builderEdge.getVal() != null && !builderEdge.getVal().isEmpty()) {
                        finalEdge.setVal(builderEdge.getVal());
                        log.debug("【边转换】设置边的值到 ProcessEdge: {} → {}, val={}", 
                                builderEdge.getSource(), builderEdge.getTarget(), builderEdge.getVal());
                    } else {
                        // 没有特殊值时，根据目标节点设置边的 val 值
                        setEdgeValByTargetNode(finalEdge, builderEdge.getTarget(), finalNodes);
                    }
                    
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
    
    /**
     * 为子图节点创建虚拟父节点（延迟拆分）
     * 
     * 流程：
     * 1. 遍历子图的所有节点（只处理真实节点，跳过虚拟节点）
     * 2. 检查其父节点是否存在
     * 3. 如果不存在，从日志/告警中提取父进程信息，创建虚拟父节点
     * 4. 批量添加虚拟父节点到子图
     * 
     * 关键点：
     * - 虚拟父节点的 parentProcessGuid 永远是 null
     * - 批量创建，避免重复
     * - 优先从日志提取，没有日志时从告警提取
     * 
     * @param subgraph 子图
     * @param traceIds traceId集合
     */
    private void createVirtualParentsForSubgraph(ProcessChainGraph subgraph, Set<String> traceIds) {
        Map<String, GraphNode> virtualParentsToAdd = new HashMap<>();
        int createdCount = 0;
        
        // 遍历子图的所有节点
        for (GraphNode node : subgraph.getAllNodes()) {
            // ✅ 跳过虚拟节点（重要！）
            if (node.isVirtual()) {
                continue;
            }
            
            String nodeId = node.getNodeId();
            String parentGuid = node.getParentProcessGuid();
            
            // ========== 情况1：普通节点（有 parentProcessGuid） ==========
            if (parentGuid != null && !parentGuid.isEmpty()) {
                // 如果父节点已经存在（真实节点），跳过
                if (subgraph.hasNode(parentGuid)) {
                    log.debug("【父进程拆分】父节点已存在: childId={}, parentId={}", nodeId, parentGuid);
                    continue;
                }
                
                // 如果虚拟父节点已经在待添加列表中，跳过
                if (virtualParentsToAdd.containsKey(parentGuid)) {
                    continue;
                }
                
                // 优先从日志中提取父进程信息
                List<RawLog> logs = node.getLogs();
                if (logs != null && !logs.isEmpty()) {
                    GraphNode virtualParent = createVirtualParentNodeFromLog(logs.get(0), parentGuid);
                    if (virtualParent != null) {
                        virtualParentsToAdd.put(parentGuid, virtualParent);
                        createdCount++;
                        log.debug("【父进程拆分】从日志创建虚拟父节点: parentId={}, childId={}", 
                                parentGuid, nodeId);
                        continue;
                    }
                    // 如果日志中信息不足，尝试从告警中提取
                    log.debug("【父进程拆分】日志中父进程信息不足，尝试从告警中提取: parentId={}, childId={}", 
                            parentGuid, nodeId);
                }
                
                // ✅ 没有日志或日志信息不足时，从告警中提取父进程信息
                List<RawAlarm> alarms = node.getAlarms();
                if (alarms != null && !alarms.isEmpty()) {
                    GraphNode virtualParent = createVirtualParentNodeFromAlarm(alarms.get(0), parentGuid);
                    if (virtualParent != null) {
                        virtualParentsToAdd.put(parentGuid, virtualParent);
                        createdCount++;
                        log.debug("【父进程拆分】从告警创建虚拟父节点: parentId={}, childId={}", 
                                parentGuid, nodeId);
                    } else {
                        log.warn("【父进程拆分】❌ 无法创建虚拟父节点（日志和告警中都缺少父进程信息）: " +
                                "parentId={}, childId={}", parentGuid, nodeId);
                    }
                }
            }
        }
        
        // 批量添加虚拟父节点到图中，并创建边
        for (Map.Entry<String, GraphNode> entry : virtualParentsToAdd.entrySet()) {
            String virtualParentId = entry.getKey();
            GraphNode virtualParent = entry.getValue();
            
            subgraph.addNode(virtualParent);
            
            // 为所有子节点创建边
            for (GraphNode node : subgraph.getAllNodes()) {
                if (node.isVirtual()) {
                    continue;
                }
                
                String parentGuid = node.getParentProcessGuid();
                
                // 普通节点，匹配 parentProcessGuid
                if (virtualParentId.equals(parentGuid)) {
                    subgraph.addEdge(virtualParentId, node.getNodeId());
                    log.debug("【父进程拆分】创建边: {} → {}", virtualParentId, node.getNodeId());
                }
            }
        }
        
        log.info("【父进程拆分】创建虚拟父节点数={}", createdCount);
    }

    /**
     * 从日志创建虚拟父节点
     * 
     * <p><b>关键</b>：虚拟父节点的 parentProcessGuid 永远是 null（未知）</p>
     * 
     * <p><b>创建条件</b>：至少需要 parentProcessId 和 parentProcessName 同时存在，
     * 否则无法创建有效的虚拟父节点。</p>
     * 
     * @param rawLog 日志数据（提取父进程信息）
     * @param parentGuid 虚拟父节点的 processGuid（nodeId）
     * @return 虚拟父节点，如果日志中父进程信息不足则返回 null
     */
    private GraphNode createVirtualParentNodeFromLog(RawLog rawLog, String parentGuid) {
        // ✅ 验证：至少需要 parentProcessId 和 parentProcessName 同时存在
        if (rawLog.getParentProcessId() == null || 
            rawLog.getParentProcessName() == null || 
            rawLog.getParentProcessName().isEmpty()) {
            log.warn("【父进程拆分】⚠️ 日志中父进程信息不足，无法创建虚拟父节点: " +
                    "parentGuid={}, parentProcessId={}, parentProcessName={}, " +
                    "eventId={}, processGuid={}", 
                    parentGuid, 
                    rawLog.getParentProcessId(), 
                    rawLog.getParentProcessName(),
                    rawLog.getEventId(),
                    rawLog.getProcessGuid());
            return null;
        }
        
        GraphNode parentNode = new GraphNode();
        
        parentNode.setNodeId(parentGuid);
        parentNode.setProcessGuid(parentGuid);
        parentNode.setParentProcessGuid(null);  // ✅ 永远是 null（未知）
        parentNode.setVirtual(true);
        parentNode.setNodeType("process");
        
        // 从日志中提取父进程信息
        parentNode.setTraceId(rawLog.getTraceId());
        parentNode.setHostAddress(rawLog.getHostAddress());
        
        // ✅ 填充父进程详细信息（用于后续展示和分析）
        parentNode.setProcessName(rawLog.getParentProcessName());
        parentNode.setProcessId(rawLog.getParentProcessId());
        if (rawLog.getParentImage() != null) {
            parentNode.setImage(rawLog.getParentImage());
        }
        if (rawLog.getParentCommandLine() != null) {
            parentNode.setCommandLine(rawLog.getParentCommandLine());
        }
        if (rawLog.getParentProcessMd5() != null) {
            parentNode.setProcessMd5(rawLog.getParentProcessMd5());
        }
        if (rawLog.getParentProcessUserName() != null) {
            parentNode.setProcessUserName(rawLog.getParentProcessUserName());
        }
        
        // ✅ 新增：将相关的日志添加到虚拟父节点
        // 注意：这里添加的是子节点的日志，但日志中包含父进程信息
        // 如果后续有父进程自己的日志，应该替换为父进程的日志
        parentNode.addLog(rawLog);
        
        log.debug("【父进程拆分】✅ 从日志创建虚拟父节点成功: parentGuid={}, processName={}, processId={}", 
                parentGuid, parentNode.getProcessName(), parentNode.getProcessId());
        
        return parentNode;
    }

    /**
     * 从告警创建虚拟父节点
     * 
     * <p><b>关键</b>：虚拟父节点的 parentProcessGuid 初始为 null（未知），
     * 后续会在 adjustVirtualParentLinks() 中调整。</p>
     * 
     * <p><b>创建条件</b>：至少需要 parentProcessId 和 parentProcessName 同时存在，
     * 否则无法创建有效的虚拟父节点。</p>
     * 
     * @param alarm 告警数据（提取父进程信息）
     * @param parentGuid 虚拟父节点的 processGuid（nodeId）
     * @return 虚拟父节点，如果告警中父进程信息不足则返回 null
     */
    private GraphNode createVirtualParentNodeFromAlarm(RawAlarm alarm, String parentGuid) {
        // ✅ 验证：至少需要 parentProcessId 和 parentProcessName 同时存在
        if (alarm.getParentProcessId() == null || 
            alarm.getParentProcessName() == null || 
            alarm.getParentProcessName().isEmpty()) {
            log.warn("【父进程拆分】⚠️ 告警中父进程信息不足，无法创建虚拟父节点: " +
                    "parentGuid={}, parentProcessId={}, parentProcessName={}, " +
                    "eventId={}, processGuid={}", 
                    parentGuid, 
                    alarm.getParentProcessId(), 
                    alarm.getParentProcessName(),
                    alarm.getEventId(),
                    alarm.getProcessGuid());
            return null;
        }
        
        GraphNode parentNode = new GraphNode();
        
        parentNode.setNodeId(parentGuid);
        parentNode.setProcessGuid(parentGuid);
        parentNode.setParentProcessGuid(null);  // ✅ 初始为 null，后续会调整
        parentNode.setVirtual(true);
        parentNode.setNodeType("process");
        
        // 从告警中提取父进程信息
        parentNode.setTraceId(alarm.getTraceId());
        parentNode.setHostAddress(alarm.getHostAddress());
        
        // ✅ 填充父进程详细信息（用于后续展示和分析）
        parentNode.setProcessName(alarm.getParentProcessName());
        parentNode.setProcessId(alarm.getParentProcessId());
        if (alarm.getParentImage() != null) {
            parentNode.setImage(alarm.getParentImage());
        }
        if (alarm.getParentCommandLine() != null) {
            parentNode.setCommandLine(alarm.getParentCommandLine());
        }
        if (alarm.getParentProcessMd5() != null) {
            parentNode.setProcessMd5(alarm.getParentProcessMd5());
        }
        if (alarm.getParentProcessUserName() != null) {
            parentNode.setProcessUserName(alarm.getParentProcessUserName());
        }
        
        // ✅ 新增：将相关的告警添加到虚拟父节点
        // 注意：这里添加的是子节点的告警，但告警中包含父进程信息
        // 如果后续有父进程自己的告警，应该替换为父进程的告警
        parentNode.addAlarm(alarm);
        
        log.debug("【父进程拆分】✅ 从告警创建虚拟父节点成功: parentGuid={}, processName={}, processId={}", 
                parentGuid, parentNode.getProcessName(), parentNode.getProcessId());
        
        return parentNode;
    }
    
    /**
     * 调整断链节点的 parentProcessGuid 并创建断链边
     * 
     * ============================================================
     * 核心功能：
     * ============================================================
     * 1. 处理所有断链节点（包括虚拟节点和真实节点）
     * 2. 检查节点是否是断链：有 parentProcessGuid 但父节点不存在
     * 3. 如果是断链，调整 parentProcessGuid 指向同 traceId 的根节点
     * 4. 为断链节点创建到根节点的边，并标记 val="断链"
     * 
     * ============================================================
     * 场景说明：
     * ============================================================
     * 
     * 【场景1】虚拟父节点有 parentProcessGuid，父节点存在 → 不需要调整
     * 
     *   REAL_PARENT (真实父节点，存在于图中)
     *    └─> VIRTUAL_PARENT (虚拟父节点)
     *         parentProcessGuid = REAL_PARENT ✓
     *         └─> CHILD (子节点)
     *   
     *   处理：保持原有的 parentProcessGuid，不需要调整
     * 
     * ----------------------------------------------------------
     * 
     * 【场景2】虚拟父节点有 parentProcessGuid，但父节点不存在 → 断链，需要调整
     * 
     *   初始状态：
     *     VIRTUAL_PARENT (虚拟父节点，断链)
     *       parentProcessGuid = MISSING_PARENT ✗ (父节点不存在)
     *       traceId = T1
     *       └─> CHILD (子节点)
     *     
     *     ROOT_T1 (同 traceId 的根节点)
     *   
     *   调整后：
     *     ROOT_T1
     *       └─[断链边, val="断链"]─> VIRTUAL_PARENT
     *                                 parentProcessGuid = ROOT_T1 ✓
     *                                 └─> CHILD
     *   
     *   操作：
     *     - 设置 VIRTUAL_PARENT.parentProcessGuid = ROOT_T1
     *     - 创建边 ROOT_T1 → VIRTUAL_PARENT，val="断链"
     * 
     * ----------------------------------------------------------
     * 
     * 【场景3】真实节点是断链（未能创建虚拟父节点）→ 需要调整
     * 
     *   初始状态：
     *     REAL_NODE (真实节点，断链)
     *       parentProcessGuid = MISSING_PARENT ✗ (父节点不存在)
     *       traceId = T1
     *       原因：日志和告警中父进程信息不足，无法创建虚拟父节点
     *     
     *     ROOT_T1 (同 traceId 的根节点)
     *   
     *   调整后：
     *     ROOT_T1
     *       └─[断链边, val="断链"]─> REAL_NODE
     *                                 parentProcessGuid = ROOT_T1 ✓
     *   
     *   操作：
     *     - 设置 REAL_NODE.parentProcessGuid = ROOT_T1
     *     - 创建边 ROOT_T1 → REAL_NODE，val="断链"
     * 
     * ----------------------------------------------------------
     * 
     * 【场景4】节点没有 parentProcessGuid (初始为 null) → 等待 EXPLORE 节点
     * 
     *   NODE (虚拟或真实节点)
     *     parentProcessGuid = null
     *     traceId = T2 (没有根节点)
     *   
     *   处理：保持 parentProcessGuid = null
     *         等 EXPLORE_ROOT_T2 节点创建后再处理
     * 
     * ============================================================
     * 关键点：
     * ============================================================
     * - 不仅虚拟节点可能是断链，真实节点也可能是断链
     * - 断链的定义：有 parentProcessGuid 但图中不存在该父节点
     * - 断链节点需要连接到同 traceId 的根节点
     * - 创建的边会被标记 val="断链"（通过 addEdge 的 val 参数）
     * - 如果该 traceId 没有根节点，保持 null，等 EXPLORE 节点创建后再处理
     * 
     * @param subgraph 子图，包含所有节点和边
     */
    private void adjustVirtualParentLinks(ProcessChainGraph subgraph) {
        int adjustedCount = 0;
        int brokenVirtualCount = 0; // 统计断链的虚拟节点数量
        int brokenRealCount = 0;    // 统计断链的真实节点数量
        Map<String, String> traceIdToRootMap = subgraph.getTraceIdToRootNodeMap();
        
        if (traceIdToRootMap == null || traceIdToRootMap.isEmpty()) {
            log.info("【断链节点调整】没有根节点映射，跳过调整");
            return;
        }
        
        for (GraphNode node : subgraph.getAllNodes()) {
            String nodeId = node.getNodeId();
            
            // ✅ 新增：跳过已经标记为断链的节点
            // 这些节点在 identifyRootNodes 中已经被标记，将由 createExploreNodes 处理
            if (node.isBroken()) {
                log.debug("【断链节点调整】跳过已标记为断链的节点（将由 EXPLORE 处理）: nodeId={}", nodeId);
                continue;
            }
            
            String traceId = node.getTraceId();
            String originalParentGuid = node.getParentProcessGuid();
            boolean isVirtual = node.isVirtual();
            
            // ===== 步骤1：检查节点是否是断链 =====
            // 断链的定义：
            // 1. 有 parentProcessGuid 但父节点不存在
            // 2. 虚拟父节点（parentProcessGuid = null）且不是根节点且入度为 0
            boolean isBrokenChain = false;
            
            if (originalParentGuid != null && !originalParentGuid.isEmpty()) {
                // 节点有 parentProcessGuid，检查图中是否存在该父节点
                if (!subgraph.hasNode(originalParentGuid)) {
                    // 父节点不存在 → 断链
                    isBrokenChain = true;
                    
                    if (isVirtual) {
                        brokenVirtualCount++;
                        log.warn("【断链节点调整】⚠️ 虚拟节点是断链: nodeId={}, " +
                                "missingParentGuid={}, traceId={}", 
                                nodeId, originalParentGuid, traceId);
                    } else {
                        brokenRealCount++;
                        log.warn("【断链节点调整】⚠️ 真实节点是断链: nodeId={}, " +
                                "missingParentGuid={}, traceId={} " +
                                "(可能是因为父进程信息不足，未能创建虚拟父节点)", 
                                nodeId, originalParentGuid, traceId);
                    }
                } else {
                    // 父节点存在 → 不是断链，保持原有的 parentProcessGuid
                    log.debug("【断链节点调整】节点的父节点存在，保持原有关系: " +
                            "nodeId={}, parentGuid={}, isVirtual={}", 
                            nodeId, originalParentGuid, isVirtual);
                    continue; // 不需要调整，跳过
                }
            } else {
                // ✅ 新增：对于虚拟父节点（parentProcessGuid = null），需要特殊判断
                // 虚拟父节点的 parentProcessGuid = null 是设计上的，但我们需要判断它是否真的断链
                if (isVirtual) {
                    // 判断虚拟父节点是否是根节点
                    boolean isRoot = node.isRoot();
                    
                    if (!isRoot) {
                        // 虚拟父节点不是根节点，检查入度
                        // 如果入度为 0，说明没有父节点指向它，应该是断链的
                        int inDegree = subgraph.getInDegree(nodeId);
                        if (inDegree == 0) {
                            // 虚拟父节点入度为 0 且不是根节点 → 断链
                            isBrokenChain = true;
                            brokenVirtualCount++;
                            log.warn("【断链节点调整】⚠️ 虚拟父节点是断链: nodeId={}, " +
                                    "入度=0, 不是根节点, traceId={}", 
                                    nodeId, traceId);
                        } else {
                            // 虚拟父节点有入度，说明有父节点指向它，不是断链
                            log.debug("【断链节点调整】虚拟父节点有父节点，不是断链: nodeId={}, 入度={}", 
                                    nodeId, inDegree);
                            continue;
                        }
                    } else {
                        // 虚拟父节点是根节点，不是断链
                        log.debug("【断链节点调整】虚拟父节点是根节点，不是断链: nodeId={}", nodeId);
                        continue;
                    }
                } else {
                    // 真实节点没有 parentProcessGuid，跳过（可能是根节点或等待 EXPLORE 节点）
                    continue;
                }
            }
            
            // ===== 步骤2：如果是断链，查找该节点对应的根节点 =====
            if (isBrokenChain) {
                String rootNodeId = traceIdToRootMap.get(traceId);
                
                if (rootNodeId != null) {
                    // 有根节点，指向根节点
                    node.setParentProcessGuid(rootNodeId);
                    
                    // ✅ 关键：创建断链边，属性="断链"
                    // 注意：边的方向是 父 → 子，即 rootNode → brokenNode
                    subgraph.addEdge(rootNodeId, nodeId, "断链");
                    
                    adjustedCount++;
                    
                    log.info("【断链节点调整】✅ 断链节点指向根节点: " +
                            "nodeId={}, rootNodeId={}, 原 parentGuid={}, " +
                            "isVirtual={}, 已创建断链边: {} → {}", 
                            nodeId, rootNodeId, originalParentGuid, isVirtual,
                            rootNodeId, nodeId);
                } else {
                    // 没有根节点，保持 null（等 EXPLORE 创建后再处理）
                    node.setParentProcessGuid(null);
                    log.debug("【断链节点调整】断链节点的 traceId={} 没有根节点，" +
                            "清空 parentProcessGuid，等待 EXPLORE 节点创建: nodeId={}", 
                            traceId, nodeId);
                }
            }
        }
        
        log.info("【断链节点调整】调整完成: 总调整数={}, 断链虚拟节点={}, 断链真实节点={}", 
                adjustedCount, brokenVirtualCount, brokenRealCount);
    }
}
