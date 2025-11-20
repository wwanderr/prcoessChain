package com.security.processchain.service;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.util.EdgePair;
import com.security.processchain.util.LogNodeSplitter;
import com.security.processchain.util.SplitResult;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * 进程链图构建器
 * 
 * 职责：
 * 1. 从原始数据（告警+日志）构建完整的图
 * 2. 应用节点拆分规则
 * 3. 合并虚拟节点和真实节点
 * 4. 返回完整的图结构
 */
@Slf4j
public class ProcessChainGraphBuilder {
    
    /**
     * 每个节点最多保留的日志数量
     * 防止单个节点累积过多日志导致性能问题
     * 
     * 场景：如果10万条日志的processGuid都相同，会累积到同一个节点
     * 限制：默认1000条，告警日志不受此限制
     */
    private static final int MAX_LOGS_PER_NODE = 1000;
    
    /**
     * 从原始数据构建图
     * 
     * @param alarms 告警列表
     * @param logs 日志列表
     * @param traceIds traceId集合
     * @return 完整的进程链图
     */
    public ProcessChainGraph buildGraph(
            List<RawAlarm> alarms,
            List<RawLog> logs,
            Set<String> traceIds) {
        
        ProcessChainGraph graph = new ProcessChainGraph();
        
        log.info("【建图】开始构建图: 告警数={}, 日志数={}, traceId数={}",
                alarms != null ? alarms.size() : 0,
                logs != null ? logs.size() : 0,
                traceIds != null ? traceIds.size() : 0);
        
        // 阶段1：添加告警节点
        if (alarms != null) {
            for (RawAlarm alarm : alarms) {
                if (alarm == null || alarm.getProcessGuid() == null) {
                    continue;
                }
                
                GraphNode node = createNodeFromAlarm(alarm);
                graph.addNode(node);
            }
            
            log.info("【建图】告警节点添加完成: {}", graph.getNodeCount());
        }
        
        // 阶段2：添加日志节点（带拆分）
        if (logs != null) {
            Map<String, GraphNode> virtualParents = new HashMap<>();
            
            for (RawLog log : logs) {
                if (log == null || log.getProcessGuid() == null) {
                    continue;
                }
                
                // 使用拆分逻辑
                SplitResult splitResult = LogNodeSplitter.splitLogNode(log);
                
                // 添加子节点（必有）
                if (splitResult.getChildNode() != null) {
                    GraphNode childNode = splitResult.getChildNode();
                    
                    // 如果子节点已存在（告警节点），合并信息
                    if (graph.hasNode(childNode.getNodeId())) {
                        GraphNode existing = graph.getNode(childNode.getNodeId());
                        // ✅ 合并日志（带数量限制）
                        mergeLogsWithLimit(existing, childNode.getLogs());
                    } else {
                        graph.addNode(childNode);
                    }
                }
                
                // 处理父节点（可能为虚拟节点）
                if (splitResult.getParentNode() != null) {
                    GraphNode parentNode = splitResult.getParentNode();
                    String parentId = parentNode.getNodeId();
                    
                    if (parentNode.isVirtual()) {
                        // 虚拟父节点：暂存，后续合并
                        if (!virtualParents.containsKey(parentId)) {
                            virtualParents.put(parentId, parentNode);
                        }
                    } else if (!graph.hasNode(parentId)) {
                        // 真实父节点：直接添加
                        graph.addNode(parentNode);
                    }
                }
                
                // 添加实体节点
                if (splitResult.getEntityNode() != null) {
                    graph.addNode(splitResult.getEntityNode());
                }
                
                // 添加边
                for (EdgePair edge : splitResult.getEdges()) {
                    graph.addEdge(edge.getSource(), edge.getTarget());
                }
            }
            
            // 阶段2.5：处理虚拟父节点
            for (Map.Entry<String, GraphNode> entry : virtualParents.entrySet()) {
                String parentId = entry.getKey();
                GraphNode virtualParent = entry.getValue();
                
                if (!graph.hasNode(parentId)) {
                    // 没有真实节点，添加虚拟节点
                    graph.addNode(virtualParent);
                    log.debug("【建图】添加虚拟父节点: {}", parentId);
                } else {
                    // 已有真实节点，不需要添加虚拟节点
                    log.debug("【建图】虚拟父节点被真实节点替代: {}", parentId);
                }
            }
            
            log.info("【建图】日志节点添加完成: 节点总数={}", graph.getNodeCount());
        }
        
        // 阶段3：建立父子边（对于没有通过拆分添加边的节点）
        // 这一步主要处理告警节点的父子关系
        if (alarms != null) {
            for (RawAlarm alarm : alarms) {
                String childGuid = alarm.getProcessGuid();
                String parentGuid = alarm.getParentProcessGuid();
                
                if (parentGuid != null && !parentGuid.isEmpty() && 
                    graph.hasNode(parentGuid) && graph.hasNode(childGuid)) {
                    // 只有当父子节点都存在时，才添加边
                    graph.addEdge(parentGuid, childGuid);
                }
            }
        }
        
        // 阶段4：图分析
        graph.identifyRootNodes(traceIds != null ? traceIds : Collections.emptySet());
        
        Set<String> cycleNodes = graph.detectCycles();
        if (!cycleNodes.isEmpty()) {
            log.warn("【建图】检测到环，包含 {} 个节点", cycleNodes.size());
            // TODO: 可以选择断开环中的某些边
        }
        
        // 输出统计信息
        log.info("【建图】构建完成: 节点数={}, 根节点={}, 断链节点={}, 告警节点={}",
                graph.getNodeCount(),
                graph.getRootNodes().size(),
                graph.getBrokenNodes().size(),
                graph.getAlarmNodes().size());
        
        return graph;
    }
    
    /**
     * 从告警创建节点
     */
    private GraphNode createNodeFromAlarm(RawAlarm alarm) {
        GraphNode node = new GraphNode();
        
        node.setNodeId(alarm.getProcessGuid());
        node.setParentProcessGuid(alarm.getParentProcessGuid());
        node.setTraceId(alarm.getTraceId());
        node.setHostAddress(alarm.getHostAddress());
        node.setNodeType("process");
        
        node.addAlarm(alarm);
        
        return node;
    }
    
    /**
     * 合并日志（带数量限制）
     * 
     * 功能：
     * 1. 告警日志：总是保留，不受数量限制
     * 2. 普通日志：检查数量上限（MAX_LOGS_PER_NODE）
     * 3. 达到上限时记录警告
     * 
     * 性能优化：
     * - 防止单个节点累积过多日志（如10万条）
     * - 避免序列化耗时和前端渲染卡顿
     * 
     * @param targetNode 目标节点
     * @param newLogs 要合并的新日志
     */
    private void mergeLogsWithLimit(GraphNode targetNode, List<RawLog> newLogs) {
        if (newLogs == null || newLogs.isEmpty()) {
            return;
        }
        
        int currentLogCount = targetNode.getLogs().size();
        int addedCount = 0;
        int skippedCount = 0;
        boolean hasWarned = false;
        
        for (RawLog log : newLogs) {
            // 告警日志：总是保留（不受数量限制）
            if (isAlarmLog(log)) {
                targetNode.addLog(log);
                addedCount++;
                continue;
            }
            
            // 普通日志：检查数量限制
            if (currentLogCount < MAX_LOGS_PER_NODE) {
                targetNode.addLog(log);
                currentLogCount++;
                addedCount++;
            } else {
                skippedCount++;
                // 只在第一次达到上限时记录警告
                if (!hasWarned) {
                    log.warn("【建图-日志累积优化】节点 {} 的日志数已达上限({}), 后续非告警日志将被忽略", 
                             targetNode.getNodeId(), MAX_LOGS_PER_NODE);
                    hasWarned = true;
                }
            }
        }
        
        if (skippedCount > 0) {
            log.info("【建图-日志累积优化】节点 {} 合并完成: 新增={}, 跳过={}, 当前总数={}", 
                     targetNode.getNodeId(), addedCount, skippedCount, targetNode.getLogs().size());
        }
    }
    
    /**
     * 判断是否是告警日志
     * 
     * 判断规则：
     * 1. 有alarmId字段
     * 2. 有threatSeverity字段
     * 3. ruleType以"/"开头（告警规则格式）
     * 
     * @param log 日志对象
     * @return true表示是告警日志
     */
    private boolean isAlarmLog(RawLog log) {
        if (log == null) {
            return false;
        }
        
        // 方式1：检查是否有告警ID
        if (log.getAlarmId() != null && !log.getAlarmId().isEmpty()) {
            return true;
        }
        
        // 方式2：检查告警严重等级
        if (log.getThreatSeverity() != null && !log.getThreatSeverity().isEmpty()) {
            return true;
        }
        
        // 方式3：检查ruleType（以/开头的通常是告警规则，如 /Malware/Backdoor）
        if (log.getRuleType() != null && log.getRuleType().startsWith("/")) {
            return true;
        }
        
        return false;
    }
}

