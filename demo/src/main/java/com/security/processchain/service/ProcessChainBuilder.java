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
    private Map<String, ProcessNode> nodeMap;
    
    // 存储所有边
    private List<ProcessEdge> edges;
    
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
     * @param traceId 溯源ID
     * @param associatedEventId 网端关联成功的eventId(可为null)
     * @return 构建结果
     */
    public ProcessChainResult buildProcessChain(List<RawAlarm> alarms, List<RawLog> logs, 
                                                String traceId, String associatedEventId) {
        if (alarms == null || alarms.isEmpty()) {
            log.warn("警告: 告警列表为空,返回空进程链");
            return new ProcessChainResult();
        }
        
        if (traceId == null || traceId.trim().isEmpty()) {
            log.error("错误: traceId为空,无法构建进程链");
            return new ProcessChainResult();
        }
        
        try {
            log.info("开始构建进程链: traceId={}, 告警数={}, 日志数={}", 
                    traceId, alarms.size(), (logs != null ? logs.size() : 0));
            
            // 记录网端关联的eventId
            if (associatedEventId != null && !associatedEventId.trim().isEmpty()) {
                this.associatedEventIds.add(associatedEventId);
                log.info("记录网端关联eventId: {}", associatedEventId);
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
                        buildBidirectionalChain(alarm, logsByProcessGuid, logsByParentProcessGuid, traceId);
                    } else {
                        // 中低危告警: 向上遍历
                        buildUpwardChain(alarm, logsByProcessGuid, traceId);
                    }
                    processedCount++;
                } catch (Exception e) {
                    log.warn("处理告警失败: eventId={}, 错误: {}", alarm.getEventId(), e.getMessage());
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
                                        String traceId) {
        if (alarm == null) {
            log.warn("告警为空,跳过双向遍历");
            return;
        }
        
        String processGuid = alarm.getProcessGuid();
        if (processGuid == null || processGuid.trim().isEmpty()) {
            log.warn("告警processGuid为空,跳过双向遍历: eventId={}", alarm.getEventId());
            return;
        }
        
        if (logsByProcessGuid == null || logsByParentProcessGuid == null) {
            log.warn("日志索引为空,跳过双向遍历");
            return;
        }
        
        // 先添加告警对应的节点
        addAlarmNode(alarm);
        
        // 检查告警节点本身是否是根节点
        if (processGuid.equals(traceId)) {
            foundRootNode = true;
            rootNodes.add(processGuid);
            log.info("告警节点本身就是根节点: processGuid={} (等于traceId)", processGuid);
        }
        
        // 添加告警对应的同级日志节点
        List<RawLog> sameLevelLogs = logsByProcessGuid.get(processGuid);
        if (sameLevelLogs != null) {
            for (RawLog rawLog : sameLevelLogs) {
                if (isValidLogType(rawLog.getLogType())) {
                    addLogNode(rawLog, true);
                    // 检查日志节点是否是根节点
                    String logProcessGuid = rawLog.getProcessGuid();
                    if (logProcessGuid != null && logProcessGuid.equals(traceId)) {
                        foundRootNode = true;
                        rootNodes.add(logProcessGuid);
                        log.info("日志节点是根节点: processGuid={} (等于traceId)", logProcessGuid);
                    }
                }
            }
        }
        
        // 向上遍历（如果告警节点不是根节点）
        if (!processGuid.equals(traceId)) {
            visitedNodesInPath.clear();
            traverseUpward(processGuid, logsByProcessGuid, traceId, 0);
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
                                   String traceId) {
        if (alarm == null) {
            log.warn("告警为空,跳过向上遍历");
            return;
        }
        
        String processGuid = alarm.getProcessGuid();
        if (processGuid == null || processGuid.trim().isEmpty()) {
            log.warn("告警processGuid为空,跳过向上遍历: eventId={}", alarm.getEventId());
            return;
        }
        
        if (logsByProcessGuid == null) {
            log.warn("日志索引为空,跳过向上遍历");
            return;
        }
        
        // 添加告警对应的节点
        addAlarmNode(alarm);
        
        // 检查告警节点本身是否是根节点
        if (processGuid.equals(traceId)) {
            foundRootNode = true;
            rootNodes.add(processGuid);
            log.info("告警节点本身就是根节点: processGuid={} (等于traceId)", processGuid);
        }
        
        // 添加告警对应的同级日志节点
        List<RawLog> sameLevelLogs = logsByProcessGuid.get(processGuid);
        if (sameLevelLogs != null) {
            for (RawLog rawLog : sameLevelLogs) {
                if (isValidLogType(rawLog.getLogType())) {
                    addLogNode(rawLog, false);
                    // 检查日志节点是否是根节点
                    String logProcessGuid = rawLog.getProcessGuid();
                    if (logProcessGuid != null && logProcessGuid.equals(traceId)) {
                        foundRootNode = true;
                        rootNodes.add(logProcessGuid);
                        log.info("日志节点是根节点: processGuid={} (等于traceId)", logProcessGuid);
                    }
                }
            }
        }
        
        // 向上遍历（如果告警节点不是根节点）
        if (!processGuid.equals(traceId)) {
            visitedNodesInPath.clear();
            traverseUpward(processGuid, logsByProcessGuid, traceId, 0);
        }
    }
    
    /**
     * 向上递归遍历
     * 
     * @param depth 当前遍历深度
     */
    private void traverseUpward(String currentProcessGuid, 
                               Map<String, List<RawLog>> logsByProcessGuid,
                               String traceId,
                               int depth) {
        // 检查深度限制
        if (depth >= MAX_TRAVERSE_DEPTH) {
            log.warn("向上遍历达到最大深度限制({}),停止遍历: {}", MAX_TRAVERSE_DEPTH, currentProcessGuid);
            return;
        }
        
        // 检查是否已访问(检测环)
        if (visitedNodesInPath.contains(currentProcessGuid)) {
            log.warn("检测到环,停止遍历: {}", currentProcessGuid);
            return;
        }
        visitedNodesInPath.add(currentProcessGuid);
        
        // 查找当前节点
        ProcessNode currentNode = nodeMap.get(currentProcessGuid);
        if (currentNode == null) {
            visitedNodesInPath.remove(currentProcessGuid);
            return;
        }
        
        // 检查当前节点是否是根节点（processGuid == traceId）
        if (currentProcessGuid.equals(traceId)) {
            foundRootNode = true;
            rootNodes.add(currentProcessGuid);
            log.info("找到根节点: processGuid={} (等于traceId)", currentProcessGuid);
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
                traverseUpward(parentProcessGuid, logsByProcessGuid, traceId, depth + 1);
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
        Iterator<Map.Entry<String, ProcessNode>> iterator = nodeMap.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, ProcessNode> entry = iterator.next();
            if (!nodesToKeep.contains(entry.getKey())) {
                iterator.remove();
                removedCount++;
            }
        }
        
        // 清理无效的边
        Iterator<ProcessEdge> edgeIterator = edges.iterator();
        while (edgeIterator.hasNext()) {
            ProcessEdge edge = edgeIterator.next();
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
        
        for (Map.Entry<String, ProcessNode> entry : nodeMap.entrySet()) {
            String processGuid = entry.getKey();
            ProcessNode node = entry.getValue();
            
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
            for (ProcessEdge edge : edges) {
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
        
        ProcessNode node = nodeMap.get(processGuid);
        if (node == null) {
            node = new ProcessNode();
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
        
        ProcessNode node = nodeMap.get(processGuid);
        if (node == null) {
            node = new ProcessNode();
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
        for (ProcessEdge edge : edges) {
            if (edge.getSource().equals(source) && edge.getTarget().equals(target)) {
                return;
            }
        }
        
        ProcessEdge edge = new ProcessEdge();
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
    public static class ProcessNode {
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
    public static class ProcessEdge {
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
     * 构建进程链并直接转换为 IncidentProcessChain
     * 这是推荐的便捷方法，避免手动转换，简化 Service 层代码
     * 
     * @param alarms 选举出的告警组
     * @param logs 查询到的原始日志
     * @param traceId 溯源ID
     * @param associatedEventId 网端关联成功的eventId(可为null)
     * @param nodeMapper 节点映射器
     * @param edgeMapper 边映射器
     * @return 事件进程链
     */
    public IncidentProcessChain buildIncidentChain(List<RawAlarm> alarms, List<RawLog> logs,
                                                   String traceId, String associatedEventId,
                                                   NodeMapper nodeMapper, EdgeMapper edgeMapper) {
        // 先构建内部进程链
        ProcessChainResult result = buildProcessChain(alarms, logs, traceId, associatedEventId);
        
        // 转换为最终返回模型
        IncidentProcessChain incident = new IncidentProcessChain();
        List<com.security.processchain.model.ProcessNode> finalNodes = new java.util.ArrayList<>();
        List<com.security.processchain.model.ProcessEdge> finalEdges = new java.util.ArrayList<>();
        
        // 获取根节点和断裂节点集合
        Set<String> rootNodeGuids = result.getRootNodes();
        Set<String> brokenNodeGuids = result.getBrokenNodes();
        
        if (result.getNodes() != null) {
            for (ProcessNode node : result.getNodes()) {
                try {
                    // 判断当前节点是否是根节点或断裂节点
                    boolean isRoot = rootNodeGuids != null && rootNodeGuids.contains(node.getProcessGuid());
                    boolean isBroken = brokenNodeGuids != null && brokenNodeGuids.contains(node.getProcessGuid());
                    
                    // 转换节点
                    com.security.processchain.model.ProcessNode finalNode = nodeMapper.toIncidentNode(node);
                    
                    // 设置 isRoot 和 isBroken 标记
                    if (finalNode.getChainNode() != null) {
                        finalNode.getChainNode().setIsRoot(isRoot);
                        finalNode.getChainNode().setIsBroken(isBroken);
                    }
                    
                    finalNodes.add(finalNode);
                } catch (Exception e) {
                    log.error("节点转换失败: processGuid={}, 错误: {}", 
                            node.getProcessGuid(), e.getMessage(), e);
                }
            }
        }
        
        if (result.getEdges() != null) {
            for (ProcessEdge edge : result.getEdges()) {
                try {
                    finalEdges.add(edgeMapper.toIncidentEdge(edge));
                } catch (Exception e) {
                    log.error("边转换失败: source={}, target={}, 错误: {}", 
                            edge.getSource(), edge.getTarget(), e.getMessage(), e);
                }
            }
        }
        
        // 为断裂节点添加 explore 节点
        if (result.getBrokenNodes() != null && !result.getBrokenNodes().isEmpty()) {
            log.info("检测到 {} 个断裂节点，开始添加 explore 节点", result.getBrokenNodes().size());
            addExploreNodesForBrokenChains(finalNodes, finalEdges, result.getBrokenNodes(), 
                    result.getRootNodes());
        }
        
        incident.setNodes(finalNodes);
        incident.setEdges(finalEdges);
        
        log.info("进程链构建并转换完成: 节点数={}, 边数={}, 根节点数={}, 断裂节点数={}", 
                finalNodes.size(), finalEdges.size(), 
                result.getRootNodes().size(), result.getBrokenNodes().size());
        
        return incident;
    }
    
    /**
     * 进程链构建结果
     */
    public static class ProcessChainResult {
        private List<ProcessNode> nodes = new ArrayList<>();
        private List<ProcessEdge> edges = new ArrayList<>();
        private boolean foundRootNode = false;
        private Set<String> rootNodes = new HashSet<>();
        private Set<String> brokenNodes = new HashSet<>();
        
        public List<ProcessNode> getNodes() {
            return nodes;
        }
        
        public void setNodes(List<ProcessNode> nodes) {
            this.nodes = nodes;
        }
        
        public List<ProcessEdge> getEdges() {
            return edges;
        }
        
        public void setEdges(List<ProcessEdge> edges) {
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
}
