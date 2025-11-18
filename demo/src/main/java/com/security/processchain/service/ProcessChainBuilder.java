package com.security.processchain.service;

import com.security.processchain.constants.ProcessChainConstants;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.util.ProcessChainPruner;
import lombok.extern.slf4j.Slf4j;
import java.util.*;

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
     * 构建进程链
     * 
     * @param alarms 选举出的告警组
     * @param logs 查询到的原始日志
     * @param traceIds 溯源ID集合（支持多个 traceId）
     * @param associatedEventIds 网端关联成功的eventId集合(可为null)
     * @return 构建结果
     */
    public ProcessChainResult buildProcessChain(List<RawAlarm> alarms, List<RawLog> logs, 
                                                Set<String> traceIds, Set<String> associatedEventIds) {
        if (alarms == null || alarms.isEmpty()) {
            log.warn("【进程链生成】-> 警告: 告警列表为空,返回空进程链");
            return new ProcessChainResult();
        }
        
        if (traceIds == null || traceIds.isEmpty()) {
            log.error("【进程链生成】-> 错误: traceIds为空,无法构建进程链");
            return new ProcessChainResult();
        }
        
        try {
            // 每次构链前重置与本次任务相关的状态，避免跨任务污染
            this.visitedNodesInPath.clear();
            this.globalVisitedUp.clear();
            this.globalVisitedDown.clear();
            this.edgeKeySet.clear();
            this.selfLoopWarned.clear();
            
            log.info("【进程链生成】-> 开始构建进程链: traceIds={}, 告警数={}, 日志数={}", 
                    traceIds, alarms.size(), (logs != null ? logs.size() : 0));
            
            // 记录网端关联的eventIds
            if (associatedEventIds != null && !associatedEventIds.isEmpty()) {
                this.associatedEventIds.addAll(associatedEventIds);
                log.info("【进程链生成】-> 记录网端关联eventIds: {}", associatedEventIds);
            }
            
            // 将日志和告警按processGuid、ParentProcessGuid索引,便于快速查找
            Map<String, List<RawLog>> logsByProcessGuid = null;
            Map<String, List<RawLog>> logsByParentProcessGuid = null;
            Map<String, List<RawAlarm>> alarmsByProcessGuid = null;
            Map<String, List<RawAlarm>> alarmsByParentProcessGuid = null;
            
            try {
                // 日志索引构建
                logsByProcessGuid = indexLogsByProcessGuid(logs);
                logsByParentProcessGuid = indexLogsByParentProcessGuid(logs);
                log.info("【进程链生成】-> 日志索引完成: 按processGuid={} 组, 按parentProcessGuid={} 组", 
                        logsByProcessGuid.size(), logsByParentProcessGuid.size());
                
                // 告警索引构建
                alarmsByProcessGuid = indexAlarmsByProcessGuid(alarms);
                alarmsByParentProcessGuid = indexAlarmsByParentProcessGuid(alarms);
                log.info("【进程链生成】-> 告警索引完成: 按processGuid={} 组, 按parentProcessGuid={} 组", 
                        alarmsByProcessGuid.size(), alarmsByParentProcessGuid.size());
            } catch (Exception e) {
                log.warn("【进程链生成】-> 索引构建失败: {}", e.getMessage());
                logsByProcessGuid = new HashMap<>();
                logsByParentProcessGuid = new HashMap<>();
                alarmsByProcessGuid = new HashMap<>();
                alarmsByParentProcessGuid = new HashMap<>();
            }
            
            // 创建链遍历上下文
            ChainTraversalContext context = new ChainTraversalContext(
                    logsByProcessGuid,
                    logsByParentProcessGuid,
                    alarmsByProcessGuid,
                    alarmsByParentProcessGuid,
                    traceIds
            );
            
            // 遍历每个告警,构建进程链
            int processedCount = 0;
            int failedCount = 0;
            
            for (RawAlarm alarm : alarms) {
                if (alarm == null) {
                    failedCount++;
                    continue;
                }
                
                try {
                    String severity = alarm.getThreatSeverity();
                    
                    if (isHighSeverity(severity)) {
                        // 高危告警: 双向遍历
                        buildBidirectionalChain(alarm, context);
                    } else {
                        // 中低危告警: 向上遍历
                        buildUpwardChain(alarm, context);
                    }
                    processedCount++;
                } catch (Exception e) {
                    log.warn("【进程链生成】-> 处理告警失败: eventId={}, 错误: {}", alarm.getEventId(), e.getMessage());
                    failedCount++;
                }
            }
            
            log.info("告警处理完成: 成功={}, 失败={}", processedCount, failedCount);
            

            
            // 检查节点数量,如果超过限制则裁剪
            if (nodeMap.size() > MAX_NODE_COUNT) {
                log.warn("【进程链生成】-> 节点数量({})超过限制({}),开始智能裁剪...", nodeMap.size(), MAX_NODE_COUNT);
                int beforePruneCount = nodeMap.size();
                try {
                    pruneNodesWithSmartStrategy();
                    log.info("【进程链生成】-> 裁剪完成: 裁剪前={}, 裁剪后={}", beforePruneCount, nodeMap.size());
                } catch (Exception e) {
                    log.error("【进程链生成】-> 节点裁剪失败: {}，已保留原始数据", e.getMessage(), e);
                    // 注意：pruneNodesWithSmartStrategy 内部已经处理了回滚，这里只是记录
                }
            }
            
            // 构建返回结果
            ProcessChainResult result = new ProcessChainResult();
            //设置节点属性，很重要，方便接下来构建
            result.setNodes(new ArrayList<>(nodeMap.values()));
            result.setEdges(edges);
            result.setFoundRootNode(foundRootNode);
            result.setRootNodes(new HashSet<>(rootNodes));
            result.setBrokenNodes(new HashSet<>(brokenNodes));
            result.setTraceIdToRootNodeMap(new HashMap<>(traceIdToRootNodeMap));
            result.setBrokenNodeToTraceId(new HashMap<>(brokenNodeToTraceId));
            
            log.info("进程链构建完成: 节点数={}, 边数={}, 根节点数={}, 断裂节点数={}, traceId映射数={}", 
                    result.getNodes().size(), result.getEdges().size(), 
                    rootNodes.size(), brokenNodes.size(), traceIdToRootNodeMap.size());
            log.info("【进程链生成】-> traceId到根节点映射: {}", traceIdToRootNodeMap);
            
            return result;
            
        } catch (Exception e) {
            log.error("错误: 构建进程链过程异常: {}", e.getMessage(), e);
            return new ProcessChainResult();
        }
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
            ProcessChainPruner.PruneContext context = new ProcessChainPruner.PruneContext(
                nodeMap,
                edges,
                rootNodes,
                associatedEventIds
            );
            
            // 执行智能裁剪
            ProcessChainPruner.PruneResult result = ProcessChainPruner.pruneNodes(context);
            
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
     * 链遍历上下文
     * 封装构建过程中需要的所有索引和配置
     */
    public static class ChainTraversalContext {
        // 日志索引
        private final Map<String, List<RawLog>> logsByProcessGuid;
        private final Map<String, List<RawLog>> logsByParentProcessGuid;
        
        // 告警索引
        private final Map<String, List<RawAlarm>> alarmsByProcessGuid;
        private final Map<String, List<RawAlarm>> alarmsByParentProcessGuid;
        
        // 溯源配置
        private final Set<String> traceIds;
        
        public ChainTraversalContext(
                Map<String, List<RawLog>> logsByProcessGuid,
                Map<String, List<RawLog>> logsByParentProcessGuid,
                Map<String, List<RawAlarm>> alarmsByProcessGuid,
                Map<String, List<RawAlarm>> alarmsByParentProcessGuid,
                Set<String> traceIds) {
            this.logsByProcessGuid = logsByProcessGuid != null ? logsByProcessGuid : new HashMap<>();
            this.logsByParentProcessGuid = logsByParentProcessGuid != null ? logsByParentProcessGuid : new HashMap<>();
            this.alarmsByProcessGuid = alarmsByProcessGuid != null ? alarmsByProcessGuid : new HashMap<>();
            this.alarmsByParentProcessGuid = alarmsByParentProcessGuid != null ? alarmsByParentProcessGuid : new HashMap<>();
            this.traceIds = traceIds != null ? traceIds : new HashSet<>();
        }
        
        // Getter 方法
        public Map<String, List<RawLog>> getLogsByProcessGuid() {
            return logsByProcessGuid;
        }
        
        public Map<String, List<RawLog>> getLogsByParentProcessGuid() {
            return logsByParentProcessGuid;
        }
        
        public Map<String, List<RawAlarm>> getAlarmsByProcessGuid() {
            return alarmsByProcessGuid;
        }
        
        public Map<String, List<RawAlarm>> getAlarmsByParentProcessGuid() {
            return alarmsByParentProcessGuid;
        }
        
        public Set<String> getTraceIds() {
            return traceIds;
        }
        
        /**
         * 检查父节点是否存在（日志或告警）
         */
        public boolean hasParentNode(String parentProcessGuid) {
            if (parentProcessGuid == null || parentProcessGuid.isEmpty()) {
                return false;
            }
            return logsByProcessGuid.containsKey(parentProcessGuid) ||
                   alarmsByProcessGuid.containsKey(parentProcessGuid);
        }
        
        /**
         * 获取父节点日志（如果存在）
         */
        public List<RawLog> getParentLogs(String parentProcessGuid) {
            return logsByProcessGuid.get(parentProcessGuid);
        }
        
        /**
         * 获取父节点告警（如果存在）
         */
        public List<RawAlarm> getParentAlarms(String parentProcessGuid) {
            return alarmsByProcessGuid.get(parentProcessGuid);
        }
        
        /**
         * 获取子节点日志列表
         */
        public List<RawLog> getChildLogs(String processGuid) {
            return logsByParentProcessGuid.get(processGuid);
        }
        
        /**
         * 获取子节点告警列表
         */
        public List<RawAlarm> getChildAlarms(String processGuid) {
            return alarmsByParentProcessGuid.get(processGuid);
        }
        
        /**
         * 检查父节点是否在日志索引中
         */
        public boolean hasParentInLogs(String parentProcessGuid) {
            return parentProcessGuid != null && !parentProcessGuid.isEmpty() &&
                   logsByProcessGuid.containsKey(parentProcessGuid);
        }
        
        /**
         * 检查父节点是否在告警索引中
         */
        public boolean hasParentInAlarms(String parentProcessGuid) {
            return parentProcessGuid != null && !parentProcessGuid.isEmpty() &&
                   alarmsByProcessGuid.containsKey(parentProcessGuid);
        }
    }
    
    /**
     * 进程节点内部类
     * 优化版本：添加了 traceId、hostAddress、isRoot、isBroken、importance 字段
     * 减少了后续查找和判断的开销
     */
    public static class ChainBuilderNode {
        private String processGuid;
        private String parentProcessGuid;
        private Boolean isAlarm = false;
        private List<RawAlarm> alarms = new ArrayList<>();
        private List<RawLog> logs = new ArrayList<>();
        
        // ========== 优化新增字段 ==========
        // traceId: 节点所属的溯源ID，避免重复从alarms/logs中提取
        private String traceId;
        
        // hostAddress: 节点所属的主机IP，避免重复从alarms/logs中提取
        private String hostAddress;
        
        // isRoot: 是否为根节点，避免重复判断 parentProcessGuid
        private Boolean isRoot = false;
        
        // isBroken: 是否为断链节点，避免重复查找 brokenNodes 集合
        private Boolean isBroken = false;
        
        // importance: 节点重要性分数，用于裁剪时快速判断
        private Double importance = 0.0;
        
        public String getProcessGuid() {
            return processGuid;
        }
        
        public void setProcessGuid(String processGuid) {
            this.processGuid = processGuid;
        }
        
        public String getParentProcessGuid() {
            return parentProcessGuid;
        }
        
        public void setParentProcessGuid(String parentProcessGuid) {
            this.parentProcessGuid = parentProcessGuid;
        }
        
        public Boolean getIsAlarm() {
            return isAlarm;
        }
        
        public void setIsAlarm(Boolean isAlarm) {
            this.isAlarm = isAlarm;
        }
        
        public List<RawAlarm> getAlarms() {
            return alarms;
        }
        
        public void addAlarm(RawAlarm alarm) {
            this.alarms.add(alarm);
            this.isAlarm = true;
            // 优化：添加告警时自动提取 traceId 和 hostAddress
            if (alarm != null) {
                if (this.traceId == null && alarm.getTraceId() != null) {
                    this.traceId = alarm.getTraceId();
                }
                if (this.hostAddress == null && alarm.getHostAddress() != null) {
                    this.hostAddress = alarm.getHostAddress();
                }
            }
        }
        
        public List<RawLog> getLogs() {
            return logs;
        }
        
        public void addLog(RawLog log) {
            this.logs.add(log);
            // 优化：添加日志时自动提取 traceId 和 hostAddress
            if (log != null) {
                if (this.traceId == null && log.getTraceId() != null) {
                    this.traceId = log.getTraceId();
                }
                if (this.hostAddress == null && log.getHostAddress() != null) {
                    this.hostAddress = log.getHostAddress();
                }
            }
        }
        
        // ========== 优化字段的 Getter/Setter ==========
        
        public String getTraceId() {
            return traceId;
        }
        
        public void setTraceId(String traceId) {
            this.traceId = traceId;
        }
        
        public String getHostAddress() {
            return hostAddress;
        }
        
        public void setHostAddress(String hostAddress) {
            this.hostAddress = hostAddress;
        }
        
        public Boolean getIsRoot() {
            return isRoot;
        }
        
        public void setIsRoot(Boolean isRoot) {
            this.isRoot = isRoot;
        }
        
        public Boolean getIsBroken() {
            return isBroken;
        }
        
        public void setIsBroken(Boolean isBroken) {
            this.isBroken = isBroken;
        }
        
        public Double getImportance() {
            return importance;
        }
        
        public void setImportance(Double importance) {
            this.importance = importance;
        }
    }
    
    /**
     * 进程边内部类
     */
    public static class ChainBuilderEdge {
        private String source;
        private String target;
        private String val;
        
        public String getSource() {
            return source;
        }
        
        public void setSource(String source) {
            this.source = source;
        }
        
        public String getTarget() {
            return target;
        }
        
        public void setTarget(String target) {
            this.target = target;
        }
        
        public String getVal() {
            return val;
        }
        
        public void setVal(String val) {
            this.val = val;
        }
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
     * 进程链构建结果
     * 优化版本：使用 NodeIndex 替代多个独立集合，简化数据结构
     */
    public static class ProcessChainResult {
        // 节点索引（包含所有节点及其多维度索引）
        private NodeIndex nodeIndex = new NodeIndex();
        
        // 边列表
        private List<ChainBuilderEdge> edges = new ArrayList<>();
        
        // traceId 到根节点ID的映射
        private Map<String, String> traceIdToRootNodeMap = new HashMap<>();
        
        // 断链节点到 traceId 的映射
        private Map<String, String> brokenNodeToTraceId = new HashMap<>();
        
        // ========== 便捷方法 ==========
        
        /**
         * 获取所有节点列表
         */
        public List<ChainBuilderNode> getNodes() {
            return new ArrayList<>(nodeIndex.getAllNodes());
        }
        
        /**
         * 设置节点列表（会重建索引）
         */
        public void setNodes(List<ChainBuilderNode> nodes) {
            nodeIndex.clear();
            if (nodes != null) {
                for (ChainBuilderNode node : nodes) {
                    nodeIndex.addNode(node);
                }
            }
        }
        
        /**
         * 获取节点索引
         */
        public NodeIndex getNodeIndex() {
            return nodeIndex;
        }
        
        /**
         * 获取边列表
         */
        public List<ChainBuilderEdge> getEdges() {
            return edges;
        }
        
        /**
         * 设置边列表
         */
        public void setEdges(List<ChainBuilderEdge> edges) {
            this.edges = edges;
        }
        
        /**
         * 是否找到了根节点
         */
        public boolean isFoundRootNode() {
            return !nodeIndex.getRootNodes().isEmpty();
        }
        
        /**
         * 获取根节点ID集合
         */
        public Set<String> getRootNodes() {
            Set<String> rootNodeIds = new HashSet<>();
            for (ChainBuilderNode node : nodeIndex.getRootNodes()) {
                rootNodeIds.add(node.getProcessGuid());
            }
            return rootNodeIds;
        }
        
        /**
         * 设置根节点（已废弃，由 NodeIndex 自动管理）
         * @deprecated 使用 NodeIndex 自动管理根节点
         */
        @Deprecated
        public void setRootNodes(Set<String> rootNodes) {
            // 兼容旧代码，不做任何操作
        }
        
        /**
         * 获取断链节点ID集合
         */
        public Set<String> getBrokenNodes() {
            Set<String> brokenNodeIds = new HashSet<>();
            for (ChainBuilderNode node : nodeIndex.getBrokenNodes()) {
                brokenNodeIds.add(node.getProcessGuid());
            }
            return brokenNodeIds;
        }
        
        /**
         * 设置断链节点（已废弃，由 NodeIndex 自动管理）
         * @deprecated 使用 NodeIndex 自动管理断链节点
         */
        @Deprecated
        public void setBrokenNodes(Set<String> brokenNodes) {
            // 兼容旧代码，不做任何操作
        }
        
        /**
         * 获取 traceId 到根节点的映射
         */
        public Map<String, String> getTraceIdToRootNodeMap() {
            return traceIdToRootNodeMap;
        }
        
        /**
         * 设置 traceId 到根节点的映射
         */
        public void setTraceIdToRootNodeMap(Map<String, String> traceIdToRootNodeMap) {
            this.traceIdToRootNodeMap = traceIdToRootNodeMap;
        }
        
        /**
         * 设置 foundRootNode（已废弃，由 NodeIndex 自动计算）
         * @deprecated 使用 isFoundRootNode() 自动计算
         */
        @Deprecated
        public void setFoundRootNode(boolean foundRootNode) {
            // 兼容旧代码，不做任何操作
        }
        
        /**
         * 获取断链节点到 traceId 的映射
         */
        public Map<String, String> getBrokenNodeToTraceId() {
            return brokenNodeToTraceId;
        }
        
        /**
         * 设置断链节点到 traceId 的映射
         */
        public void setBrokenNodeToTraceId(Map<String, String> brokenNodeToTraceId) {
            this.brokenNodeToTraceId = brokenNodeToTraceId;
        }
    }
    
    /**
     * 直接构建最终的 IncidentProcessChain（一步到位）
     * 支持多个 traceId 和多个 associatedEventId
     * 
     * @param alarms 告警列表
     * @param logs 日志列表
     * @param traceIds 追踪 ID 集合
     * @param associatedEventIds 关联事件 ID 集合
     * @param nodeMapper 节点映射器
     * @param edgeMapper 边映射器
     * @return 完整的 IncidentProcessChain
     */
    public IncidentProcessChain buildIncidentChain(
            List<RawAlarm> alarms, 
            List<RawLog> logs,
            Set<String> traceIds,
            Set<String> associatedEventIds,
            NodeMapper nodeMapper, 
            EdgeMapper edgeMapper) {
        
        if (alarms == null || alarms.isEmpty()) {
            log.warn("【进程链生成】-> 警告: 告警列表为空，返回空进程链");
            return new IncidentProcessChain();
        }
        
        if (traceIds == null || traceIds.isEmpty()) {
            log.error("【进程链生成】-> 错误: traceIds为空，无法构建进程链");
            return new IncidentProcessChain();
        }
        
        try {
            log.info("【进程链生成】-> 开始构建进程链: traceIds={}, 关联事件数={}, 告警数={}, 日志数={}", 
                    traceIds, 
                    (associatedEventIds != null ? associatedEventIds.size() : 0),
                    alarms.size(), 
                    (logs != null ? logs.size() : 0));
            
            // 构建内部结果
            ProcessChainResult result = buildProcessChain(alarms, logs, traceIds, associatedEventIds);
            
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
                
                // ✅ 关键修复：将更新后的 traceIdToRootNodeMap 同步回 ProcessChainBuilder 的成员变量
                // 因为 addExploreNodesForBrokenChains() 会更新 result 中的映射
                this.traceIdToRootNodeMap = result.getTraceIdToRootNodeMap();
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
