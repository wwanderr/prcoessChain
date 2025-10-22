package com.security.processchain.service;

import com.security.processchain.constants.ProcessChainConstants;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
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
    
    public ProcessChainBuilder() {
        this.nodeMap = new HashMap<>();
        this.edges = new ArrayList<>();
        this.rootNodes = new HashSet<>();
        this.foundRootNode = false;
        this.visitedNodesInPath = new HashSet<>();
        this.associatedEventIds = new HashSet<>();
        this.brokenNodes = new HashSet<>();
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
                log.warn("节点数量({})超过限制({}),开始裁剪...", nodeMap.size(), MAX_NODE_COUNT);
                try {
                    pruneNodes();
                } catch (Exception e) {
                    log.error("节点裁剪失败: {}", e.getMessage(), e);
                }
            }
            
            // 构建返回结果
            ProcessChainResult result = new ProcessChainResult();
            result.setNodes(new ArrayList<>(nodeMap.values()));
            result.setEdges(edges);
            result.setFoundRootNode(foundRootNode);
            result.setRootNodes(new HashSet<>(rootNodes));
            result.setBrokenNodes(new HashSet<>(brokenNodes));
            
            log.info("进程链构建完成: 节点数={}, 边数={}, 根节点数={}, 断裂节点数={}", 
                    result.getNodes().size(), result.getEdges().size(), 
                    rootNodes.size(), brokenNodes.size());
            
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
        
        // 先添加告警对应的节点
        addAlarmNode(alarm);
        
        // 检查告警节点本身是否是根节点
        if (traceIds.contains(processGuid)) {
            foundRootNode = true;
            rootNodes.add(processGuid);
            log.info("【进程链生成】-> 告警节点本身就是根节点: processGuid={} (匹配traceIds)", processGuid);
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
            log.info("【进程链生成】-> 告警节点本身就是根节点: processGuid={} (匹配traceIds)", processGuid);
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
        if (traceIds.contains(currentProcessGuid)) {
            foundRootNode = true;
            rootNodes.add(currentProcessGuid);
            log.info("【进程链生成】-> 找到根节点: processGuid={} (匹配traceIds)", currentProcessGuid);
            visitedNodesInPath.remove(currentProcessGuid);
            return;
        }
        
        String parentProcessGuid = currentNode.getParentProcessGuid();
        
        // 检查父节点日志是否存在于原始日志中
        // 如果父节点不在 logsByProcessGuid 中，说明断链了
        if (parentProcessGuid == null || parentProcessGuid.isEmpty() || 
            !logsByProcessGuid.containsKey(parentProcessGuid)) {
            
            // 断链：当前节点的父进程在原始日志中不存在
            // 当前节点标记为断裂节点，停止向上追溯
            brokenNodes.add(currentProcessGuid);
            log.warn("断链检测: 当前节点 {} 的父节点 {} 在原始日志中不存在，标记为断裂节点", 
                    currentProcessGuid, parentProcessGuid);
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
     * 裁剪节点
     * 裁剪规则:
     * 1. 优先保留网端关联成功的告警节点及其相关节点
     * 2. 优先保留高危告警节点及其相关节点
     * 3. 保留中危告警节点
     * 4. 最后考虑低危和非告警节点
     */
    private void  pruneNodes() {
        // 计算每个节点的重要性分数
        Map<String, Integer> nodeScores = calculateNodeScores();
        
        // 按分数排序
        List<Map.Entry<String, Integer>> sortedNodes = new ArrayList<>(nodeScores.entrySet());
        sortedNodes.sort((a, b) -> b.getValue().compareTo(a.getValue()));
        
        // 保留前MAX_NODE_COUNT个节点
        Set<String> nodesToKeep = new HashSet<>();
        for (int i = 0; i < Math.min(MAX_NODE_COUNT, sortedNodes.size()); i++) {
            nodesToKeep.add(sortedNodes.get(i).getKey());
        }
        
        // 移除低分节点
        int removedCount = 0;
        Iterator<Map.Entry<String, ChainBuilderNode>> iterator = nodeMap.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, ChainBuilderNode> entry = iterator.next();
            if (!nodesToKeep.contains(entry.getKey())) {
                iterator.remove();
                removedCount++;
            }
        }
        
        // 清理无效的边
        Iterator<ChainBuilderEdge> edgeIterator = edges.iterator();
        while (edgeIterator.hasNext()) {
            ChainBuilderEdge edge = edgeIterator.next();
            if (!nodeMap.containsKey(edge.getSource()) || !nodeMap.containsKey(edge.getTarget())) {
                edgeIterator.remove();
            }
        }
        
        log.info("裁剪完成: 移除了 {} 个节点, 保留 {} 个节点", removedCount, nodeMap.size());
    }
    
    /**
     * 计算节点重要性分数
     * 分数越高,节点越重要
     */
    private Map<String, Integer> calculateNodeScores() {
        Map<String, Integer> scores = new HashMap<>();
        
        for (Map.Entry<String, ChainBuilderNode> entry : nodeMap.entrySet()) {
            String processGuid = entry.getKey();
            ChainBuilderNode node = entry.getValue();
            
            int score = 0;
            
            // 1. 网端关联成功的告警节点: +1000分
            if (node.getIsAlarm()) {
                for (RawAlarm alarm : node.getAlarms()) {
                    if (associatedEventIds.contains(alarm.getEventId())) {
                        score += 1000;
                        break;
                    }
                }
            }
            
            // 2. 告警节点根据威胁等级加分
            if (node.getIsAlarm()) {
                for (RawAlarm alarm : node.getAlarms()) {
                    String severity = alarm.getThreatSeverity();
                    if (isHighSeverity(severity)) {
                        score += 100; // 高危: +100分
                    } else if (isMediumSeverity(severity)) {
                        score += 50;  // 中危: +50分
                    } else {
                        score += 20;  // 低危: +20分
                    }
                }
            }
            
            // 3. 根节点: +80分
            if (rootNodes.contains(processGuid)) {
                score += 80;
            }
            
            // 4. 根据节点的连接数加分(度中心性)
            int connectionCount = 0;
            for (ChainBuilderEdge edge : edges) {
                if (edge.getSource().equals(processGuid) || edge.getTarget().equals(processGuid)) {
                    connectionCount++;
                }
            }
            score += Math.min(connectionCount * 2, 30); // 最多+30分
            
            // 5. 有日志数据的节点: +10分
            if (!node.getLogs().isEmpty()) {
                score += 10;
            }
            
            // 6. process类型的节点优先于其他类型: +5分
            boolean hasProcessLog = false;
            for (RawLog log : node.getLogs()) {
                if ("process".equalsIgnoreCase(log.getLogType())) {
                    hasProcessLog = true;
                    break;
                }
            }
            if (hasProcessLog) {
                score += 5;
            }
            
            scores.put(processGuid, score);
        }
        
        return scores;
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
        
        // 添加告警信息
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
     */
    public static class ChainBuilderNode {
        private String processGuid;
        private String parentProcessGuid;
        private Boolean isAlarm = false;
        private List<RawAlarm> alarms = new ArrayList<>();
        private List<RawLog> logs = new ArrayList<>();
        
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
        }
        
        public List<RawLog> getLogs() {
            return logs;
        }
        
        public void addLog(RawLog log) {
            this.logs.add(log);
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
     * 为断裂的进程链添加 explore 节点
     * 
     * @param finalNodes 最终节点列表
     * @param finalEdges 最终边列表
     * @param brokenNodes 断裂节点集合（processGuid）
     * @param rootNodes 根节点集合（processGuid）
     */
    private void addExploreNodesForBrokenChains(
            List<com.security.processchain.model.ProcessNode> finalNodes,
            List<com.security.processchain.model.ProcessEdge> finalEdges,
            Set<String> brokenNodes,
            Set<String> rootNodes) {
        
        for (String brokenNodeGuid : brokenNodes) {
            // 创建 explore 节点
            String exploreNodeId = "explore_" + brokenNodeGuid;
            
            com.security.processchain.model.ProcessNode exploreNode = 
                    new com.security.processchain.model.ProcessNode();
            exploreNode.setNodeId(exploreNodeId);
            exploreNode.setIsChainNode(true);
            exploreNode.setLogType(NodeType.EXPLORE);
            
            ChainNode exploreChainNode = new ChainNode();
            exploreChainNode.setIsRoot(false);
            exploreChainNode.setIsBroken(false);
            exploreChainNode.setIsAlarm(false);
            
            exploreNode.setChainNode(exploreChainNode);
            exploreNode.setStoryNode(null);
            
            // 添加 explore 节点到列表
            finalNodes.add(exploreNode);
            
            // 创建边：explore -> 断裂节点
            com.security.processchain.model.ProcessEdge exploreEdge = 
                    new com.security.processchain.model.ProcessEdge();
            exploreEdge.setSource(exploreNodeId);
            exploreEdge.setTarget(brokenNodeGuid);
            exploreEdge.setVal("1");
            
            finalEdges.add(exploreEdge);
            
            log.info("为断裂节点 {} 添加了 explore 节点: {}", brokenNodeGuid, exploreNodeId);
        }
    }
    
    /**
     * 构建进程链并直接转换为 IncidentProcessChain（已废弃，保留以兼容旧代码）
     * 推荐使用接受 Set<String> traceIds 和 Set<String> associatedEventIds 的新版本
     * 
     * @param alarms 选举出的告警组
     * @param logs 查询到的原始日志
     * @param traceId 溯源ID
     * @param associatedEventId 网端关联成功的eventId(可为null)
     * @param nodeMapper 节点映射器
     * @param edgeMapper 边映射器
     * @return 事件进程链
     * @deprecated 使用 buildIncidentChain(alarms, logs, Set<String> traceIds, Set<String> associatedEventIds, ...)
     */
    @Deprecated
    public IncidentProcessChain buildIncidentChain(List<RawAlarm> alarms, List<RawLog> logs,
                                                   String traceId, String associatedEventId,
                                                   NodeMapper nodeMapper, EdgeMapper edgeMapper) {
        // 转换为新方法（使用 Set）
        Set<String> traceIds = new HashSet<>();
        if (traceId != null && !traceId.trim().isEmpty()) {
            traceIds.add(traceId);
        }
        
        Set<String> associatedEventIds = new HashSet<>();
        if (associatedEventId != null && !associatedEventId.trim().isEmpty()) {
            associatedEventIds.add(associatedEventId);
        }
        
        return buildIncidentChain(alarms, logs, traceIds, associatedEventIds, nodeMapper, edgeMapper);
    }
    
    /**
     * 进程链构建结果
     */
    public static class ProcessChainResult {
        private List<ChainBuilderNode> nodes = new ArrayList<>();
        private List<ChainBuilderEdge> edges = new ArrayList<>();
        private boolean foundRootNode = false;
        private Set<String> rootNodes = new HashSet<>();
        private Set<String> brokenNodes = new HashSet<>();
        
        public List<ChainBuilderNode> getNodes() {
            return nodes;
        }
        
        public void setNodes(List<ChainBuilderNode> nodes) {
            this.nodes = nodes;
        }
        
        public List<ChainBuilderEdge> getEdges() {
            return edges;
        }
        
        public void setEdges(List<ChainBuilderEdge> edges) {
            this.edges = edges;
        }
        
        public boolean isFoundRootNode() {
            return foundRootNode;
        }
        
        public void setFoundRootNode(boolean foundRootNode) {
            this.foundRootNode = foundRootNode;
        }
        
        public Set<String> getRootNodes() {
            return rootNodes;
        }
        
        public void setRootNodes(Set<String> rootNodes) {
            this.rootNodes = rootNodes;
        }
        
        public Set<String> getBrokenNodes() {
            return brokenNodes;
        }
        
        public void setBrokenNodes(Set<String> brokenNodes) {
            this.brokenNodes = brokenNodes;
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
            
            // 转换节点
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
            
            // 转换边
            if (result.getEdges() != null) {
                for (ChainBuilderEdge builderEdge : result.getEdges()) {
                    com.security.processchain.model.ProcessEdge finalEdge = edgeMapper.toIncidentEdge(builderEdge);
                    finalEdges.add(finalEdge);
                }
            }
            
            // 添加 Explore 节点（如果有断链）
            if (result.getBrokenNodes() != null && !result.getBrokenNodes().isEmpty()) {
                addExploreNodesForBrokenChains(finalNodes, finalEdges, 
                        result.getBrokenNodes(), result.getRootNodes());
            }
            
            incidentChain.setNodes(finalNodes);
            incidentChain.setEdges(finalEdges);
            
            log.info("【进程链生成】-> IncidentProcessChain 构建完成: 节点数={}, 边数={}", 
                    finalNodes.size(), finalEdges.size());
            
            return incidentChain;
            
        } catch (Exception e) {
            log.error("【进程链生成】-> 构建 IncidentProcessChain 失败: {}", e.getMessage(), e);
            return new IncidentProcessChain();
        }
    }
}
