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
    
    // 根节点集合
    private Set<String> rootNodes;
    
    // 是否找到了根节点
    private boolean foundRootNode;
    
    // 已访问节点集合,用于检测环
    private Set<String> visitedNodesInPath;
    
    // 网端关联成功的告警eventId集合
    private Set<String> associatedEventIds;
    
    // 断裂节点集合（找不到根节点的最顶端节点）
    private Set<String> brokenNodes;
    
    // 断链节点到 traceId 的映射（用于将断链连接到正确的 EXPLORE）
    private Map<String, String> brokenNodeToTraceId;
    
    // traceId 到根节点ID的映射（用于网端桥接）
    private Map<String, String> traceIdToRootNodeMap;
    
    public ProcessChainBuilder() {
        this.nodeMap = new HashMap<>();
        this.edges = new ArrayList<>();
        this.rootNodes = new HashSet<>();
        this.foundRootNode = false;
        this.visitedNodesInPath = new HashSet<>();
        this.associatedEventIds = new HashSet<>();
        this.brokenNodes = new HashSet<>();
        this.brokenNodeToTraceId = new HashMap<>();
        this.traceIdToRootNodeMap = new HashMap<>();
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
            log.info("【进程链生成】-> 开始构建进程链: traceIds={}, 告警数={}, 日志数={}", 
                    traceIds, alarms.size(), (logs != null ? logs.size() : 0));
            
            // 记录网端关联的eventIds
            if (associatedEventIds != null && !associatedEventIds.isEmpty()) {
                this.associatedEventIds.addAll(associatedEventIds);
                log.info("【进程链生成】-> 记录网端关联eventIds: {}", associatedEventIds);
            }
            
            // 将日志按processGuid、ParentProcessGuid索引,便于快速查找
            Map<String, List<RawLog>> logsByProcessGuid = null;
            Map<String, List<RawLog>> logsByParentProcessGuid = null;
            
            try {
                //日志kv存储
                logsByProcessGuid = indexLogsByProcessGuid(logs);
                logsByParentProcessGuid = indexLogsByParentProcessGuid(logs);
                log.info("日志索引完成: 按processGuid={} 组, 按parentProcessGuid={} 组", 
                        logsByProcessGuid.size(), logsByParentProcessGuid.size());
            } catch (Exception e) {
                log.warn("日志索引失败: {}", e.getMessage());
                logsByProcessGuid = new HashMap<>();
                logsByParentProcessGuid = new HashMap<>();
            }
            
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
                        buildBidirectionalChain(alarm, logsByProcessGuid, logsByParentProcessGuid, traceIds);
                    } else {
                        // 中低危告警: 向上遍历
                        buildUpwardChain(alarm, logsByProcessGuid, traceIds);
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
    private void buildBidirectionalChain(RawAlarm alarm, 
                                        Map<String, List<RawLog>> logsByProcessGuid,
                                        Map<String, List<RawLog>> logsByParentProcessGuid,
                                        Set<String> traceIds) {
        if (alarm == null) {
            log.warn("【进程链生成】-> 告警为空,跳过双向遍历");
            return;
        }
        
        String processGuid = alarm.getProcessGuid();
        if (processGuid == null || processGuid.trim().isEmpty()) {
            log.warn("【进程链生成】-> 告警processGuid为空,跳过双向遍历: eventId={}", alarm.getEventId());
            return;
        }
        
        if (logsByProcessGuid == null || logsByParentProcessGuid == null) {
            log.warn("【进程链生成】-> 日志索引为空,跳过双向遍历");
            return;
        }
        
        // 先添加告警对应的节点，包含很多重要数据
        addAlarmNode(alarm);
        
        // 检查告警节点本身是否是根节点
        if (traceIds.contains(processGuid)) {
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
        List<RawLog> sameLevelLogs = logsByProcessGuid.get(processGuid);
        if (sameLevelLogs != null) {
            for (RawLog rawLog : sameLevelLogs) {
                if (isValidLogType(rawLog.getLogType())) {
                    addLogNode(rawLog, true);
                    // 检查日志节点是否是根节点
                    String logProcessGuid = rawLog.getProcessGuid();
                    if (logProcessGuid != null && traceIds.contains(logProcessGuid)) {
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
        if (!traceIds.contains(processGuid)) {
            visitedNodesInPath.clear();
            traverseUpward(processGuid, logsByProcessGuid, traceIds, 0);
        }
        
        // 向下遍历
        visitedNodesInPath.clear();
        traverseDownward(processGuid, logsByParentProcessGuid, logsByProcessGuid, 0);
    }
    
    /**
     * 构建向上进程链(用于中低危告警)
     */
    private void buildUpwardChain(RawAlarm alarm, 
                                   Map<String, List<RawLog>> logsByProcessGuid,
                                   Set<String> traceIds) {
        if (alarm == null) {
            log.warn("【进程链生成】-> 告警为空,跳过向上遍历");
            return;
        }
        
        String processGuid = alarm.getProcessGuid();
        if (processGuid == null || processGuid.trim().isEmpty()) {
            log.warn("【进程链生成】-> 告警processGuid为空,跳过向上遍历: eventId={}", alarm.getEventId());
            return;
        }
        
        if (logsByProcessGuid == null) {
            log.warn("【进程链生成】-> 日志索引为空,跳过向上遍历");
            return;
        }
        
        // 添加告警对应的节点
        addAlarmNode(alarm);
        
        // 检查告警节点本身是否是根节点
        if (traceIds.contains(processGuid)) {
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
        List<RawLog> sameLevelLogs = logsByProcessGuid.get(processGuid);
        if (sameLevelLogs != null) {
            for (RawLog rawLog : sameLevelLogs) {
                if (isValidLogType(rawLog.getLogType())) {
                    addLogNode(rawLog, false);
                    // 检查日志节点是否是根节点
                    String logProcessGuid = rawLog.getProcessGuid();
                    if (logProcessGuid != null && traceIds.contains(logProcessGuid)) {
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
        if (!traceIds.contains(processGuid)) {
            visitedNodesInPath.clear();
            traverseUpward(processGuid, logsByProcessGuid, traceIds, 0);
        }
    }
    
    /**
     * 向上递归遍历
     * 
     * @param depth 当前遍历深度
     */
    private void traverseUpward(String currentProcessGuid, 
                               Map<String, List<RawLog>> logsByProcessGuid,
                               Set<String> traceIds,
                               int depth) {
        // 检查深度限制
        if (depth >= MAX_TRAVERSE_DEPTH) {
            log.warn("【进程链生成】-> 向上遍历达到最大深度限制({}),停止遍历: {}", MAX_TRAVERSE_DEPTH, currentProcessGuid);
            return;
        }
        
        // 检查是否已访问(检测环)
        if (visitedNodesInPath.contains(currentProcessGuid)) {
            log.warn("【进程链生成】-> 检测到环,停止遍历: {}", currentProcessGuid);
            return;
        }
        visitedNodesInPath.add(currentProcessGuid);
        
        // 查找当前节点
        ChainBuilderNode currentNode = nodeMap.get(currentProcessGuid);
        if (currentNode == null) {
            visitedNodesInPath.remove(currentProcessGuid);
            return;
        }
        
        // 检查当前节点是否是根节点（processGuid 匹配任意一个 traceId）
        // 终止条件1: 找到根节点
        if (traceIds.contains(currentProcessGuid)) {
            foundRootNode = true;
            rootNodes.add(currentProcessGuid);
            // ✅ 优化：设置节点的 isRoot 属性（用于 NodeIndex）
            currentNode.setIsRoot(true);
            // 记录映射：当 processGuid 在 traceIds 中时，processGuid 本身就是 traceId
            traceIdToRootNodeMap.put(currentProcessGuid, currentProcessGuid);
            log.info("【进程链生成】-> 找到根节点: processGuid={} (匹配traceIds), 记录映射: traceId={} -> rootNodeId={}", 
                    currentProcessGuid, currentProcessGuid, currentProcessGuid);
            visitedNodesInPath.remove(currentProcessGuid);
            return;
        }
        
        String parentProcessGuid = currentNode.getParentProcessGuid();

        // 检查父节点日志是否存在于原始日志中
        // 终止条件2: 父节点日志缺失（断链）
        if (parentProcessGuid == null || parentProcessGuid.isEmpty() ||
                !logsByProcessGuid.containsKey(parentProcessGuid)) {

            // 重要：先检查当前节点是否是根节点
            if (traceIds.contains(currentProcessGuid)) {
                // 场景1: 当前节点是根节点（parentProcessGuid 为空或父节点缺失是存在的）
                foundRootNode = true;
                rootNodes.add(currentProcessGuid);
                currentNode.setIsRoot(true);
                traceIdToRootNodeMap.put(currentProcessGuid, currentProcessGuid);
                log.info("【进程链生成】-> 找到根节点: processGuid={} (父节点为空或缺失)",
                        currentProcessGuid);
                visitedNodesInPath.remove(currentProcessGuid);
                return;
            }

            // 场景2: 当前节点不是根节点，但父节点日志缺失 → 断链
            // 原因：无法继续向上追溯，进程链在此处断裂
            brokenNodes.add(currentProcessGuid);
            currentNode.setIsBroken(true);
            nodeIndex.updateNode(currentNode);  // 更新索引

            // 记录断链节点的 traceId，用于后续创建对应的 EXPLORE_ROOT 节点
            String nodeTraceId = extractTraceIdFromNode(currentNode);
            if (nodeTraceId != null && !nodeTraceId.isEmpty()) {
                brokenNodeToTraceId.put(currentProcessGuid, nodeTraceId);
                log.warn("【断链检测】-> 节点 {} (traceId={}) 的父节点 {} 日志缺失，标记为断链节点",
                        currentProcessGuid, nodeTraceId,
                        parentProcessGuid != null ? parentProcessGuid : "null");
            } else {
                log.warn("【断链检测】-> 节点 {} 的父节点 {} 日志缺失，标记为断链节点（未提取到traceId）",
                        currentProcessGuid,
                        parentProcessGuid != null ? parentProcessGuid : "null");
            }

            visitedNodesInPath.remove(currentProcessGuid);
            return;
        }
        
        // 父节点存在，获取父节点日志
        List<RawLog> parentLogs = logsByProcessGuid.get(parentProcessGuid);
        
        // 添加父节点
        for (RawLog log : parentLogs) {
            if (isValidLogType(log.getLogType()) && 
                parentProcessGuid.equals(log.getProcessGuid())) {
                
                addLogNode(log, false);
                
                // 添加边: 父节点 -> 当前节点
                addEdge(parentProcessGuid, currentProcessGuid);
                
                // 继续向上递归
                traverseUpward(parentProcessGuid, logsByProcessGuid, traceIds, depth + 1);
                break;
            }
        }
        // 回溯时清理，允许其他路径访问该节点
        visitedNodesInPath.remove(currentProcessGuid);
    }
    
    /**
     * 向下递归遍历
     * 
     * @param depth 当前遍历深度
     */
    private void traverseDownward(String currentProcessGuid,
                                  Map<String, List<RawLog>> logsByParentProcessGuid,
                                  Map<String, List<RawLog>> logsByProcessGuid,
                                  int depth) {
        // 检查深度限制
        if (depth >= MAX_TRAVERSE_DEPTH) {
            log.warn("向下遍历达到最大深度限制({}),停止遍历: {}", MAX_TRAVERSE_DEPTH, currentProcessGuid);
            return;
        }
        
        // 检查是否已访问(检测环)
        if (visitedNodesInPath.contains(currentProcessGuid)) {
            log.warn("检测到环,停止遍历: {}", currentProcessGuid);
            return;
        }
        visitedNodesInPath.add(currentProcessGuid);
        
        // 查找子节点
        List<RawLog> childLogs = logsByParentProcessGuid.get(currentProcessGuid);
        if (childLogs == null || childLogs.isEmpty()) {
            visitedNodesInPath.remove(currentProcessGuid);
            return;
        }
        
        // 遍历所有子节点
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
            List<RawLog> sameLevelLogs = logsByProcessGuid.get(childProcessGuid);
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
            traverseDownward(childProcessGuid, logsByParentProcessGuid, logsByProcessGuid, depth + 1);
        }
        
        visitedNodesInPath.remove(currentProcessGuid);
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
        // 检查边是否已存在
        for (ChainBuilderEdge edge : edges) {
            if (edge.getSource().equals(source) && edge.getTarget().equals(target)) {
                return;
            }
        }
        
        ChainBuilderEdge edge = new ChainBuilderEdge();
        edge.setSource(source);
        edge.setTarget(target);
        edges.add(edge);
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
            exploreNode.setLogType(NodeType.EXPLORE);
            
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
