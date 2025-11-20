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
            
            for (RawLog rawLog : logs) {
                if (rawLog == null || rawLog.getProcessGuid() == null) {
                    continue;
                }
                
                // 使用拆分逻辑
                SplitResult splitResult = LogNodeSplitter.splitLogNode(rawLog);
                
                // 添加子节点（必有）
                if (splitResult.getChildNode() != null) {
                    GraphNode childNode = splitResult.getChildNode();
                    
                    // 如果子节点已存在（告警节点），合并信息
                    if (graph.hasNode(childNode.getNodeId())) {
                        GraphNode existing = graph.getNode(childNode.getNodeId());
                        
                        // ✅ 如果告警节点的 nodeType 不是 "process"，但日志节点是 "process"
                        // 保持告警节点的类型（告警类型优先）
                        if (!"process".equals(existing.getNodeType()) && "process".equals(childNode.getNodeType())) {
                            log.debug("【建图】保持告警节点类型: nodeId={}, 告警nodeType={}, 日志nodeType={}", 
                                    existing.getNodeId(), existing.getNodeType(), childNode.getNodeType());
                        }
                        
                        // 合并日志（带数量限制）
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
                            log.debug("【建图-父节点】暂存虚拟父节点: parentId={}, isVirtual={}", 
                                    parentId, parentNode.isVirtual());
                        }
                    } else if (!graph.hasNode(parentId)) {
                        // 真实父节点：直接添加
                        graph.addNode(parentNode);
                        log.debug("【建图-父节点】添加真实父节点: parentId={}, isVirtual={}", 
                                parentId, parentNode.isVirtual());
                    } else {
                        log.debug("【建图-父节点】父节点已存在，跳过: parentId={}", parentId);
                    }
                }
                
                // 添加实体节点
                if (splitResult.getEntityNode() != null) {
                    GraphNode entityNode = splitResult.getEntityNode();
                    graph.addNode(entityNode);
                    log.info("【建图-实体节点】添加实体节点: nodeId={}, nodeType={}", 
                            entityNode.getNodeId(), entityNode.getNodeType());
                }
                
                // 添加边
                for (EdgePair edge : splitResult.getEdges()) {
                    graph.addEdge(edge.getSource(), edge.getTarget());
                }
            }
            
            // 阶段2.5：处理虚拟父节点
            log.info("【建图-阶段2.5】处理虚拟父节点: 暂存数量={}", virtualParents.size());
            int addedVirtualParentCount = 0;
            int replacedVirtualParentCount = 0;
            
            for (Map.Entry<String, GraphNode> entry : virtualParents.entrySet()) {
                String parentId = entry.getKey();
                GraphNode virtualParent = entry.getValue();
                
                if (!graph.hasNode(parentId)) {
                    // 没有真实节点，添加虚拟节点
                    graph.addNode(virtualParent);
                    addedVirtualParentCount++;
                    log.debug("【建图】添加虚拟父节点: parentId={}, nodeType={}", 
                            parentId, virtualParent.getNodeType());
                } else {
                    // 已有真实节点，不需要添加虚拟节点
                    replacedVirtualParentCount++;
                    log.debug("【建图】虚拟父节点被真实节点替代: parentId={}", parentId);
                }
            }
            
            log.info("【建图-阶段2.5】虚拟父节点处理完成: 添加={}, 替代={}", 
                    addedVirtualParentCount, replacedVirtualParentCount);
            
            // 统计各类型节点数量
            int processNodeCount = 0;
            int entityNodeCount = 0;
            int fileEntityCount = 0;
            int domainEntityCount = 0;
            int networkEntityCount = 0;
            int registryEntityCount = 0;
            
            for (GraphNode node : graph.getAllNodes()) {
                String nodeType = node.getNodeType();
                if (nodeType != null && nodeType.endsWith("_entity")) {
                    entityNodeCount++;
                    if (nodeType.equals("file_entity")) {
                        fileEntityCount++;
                    } else if (nodeType.equals("domain_entity")) {
                        domainEntityCount++;
                    } else if (nodeType.equals("network_entity")) {
                        networkEntityCount++;
                    } else if (nodeType.equals("registry_entity")) {
                        registryEntityCount++;
                    }
                } else {
                    processNodeCount++;
                }
            }
            
            log.info("【建图】日志节点添加完成: 节点总数={}, 进程节点={}, 实体节点={} (file={}, domain={}, network={}, registry={})", 
                    graph.getNodeCount(), processNodeCount, entityNodeCount,
                    fileEntityCount, domainEntityCount, networkEntityCount, registryEntityCount);
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
        
        // ✅ 从告警中获取 logType
        String logType = alarm.getLogType();
        if (logType == null || logType.isEmpty()) {
            // 如果告警没有 logType，默认为 process
            logType = "process";
            log.debug("【建图】告警没有logType，默认设置为process: processGuid={}", alarm.getProcessGuid());
        }
        node.setNodeType(logType);
        
        log.debug("【建图】从告警创建节点: processGuid={}, logType={}, nodeType={}", 
                alarm.getProcessGuid(), alarm.getLogType(), node.getNodeType());
        
        node.addAlarm(alarm);
        
        return node;
    }
    
    /**
     * 合并日志（带数量限制）
     * 
     * 功能：
     * 1. 告警节点：所有日志都保留，不受数量限制
     * 2. 非告警节点：检查数量上限（MAX_LOGS_PER_NODE）
     * 3. 达到上限时记录警告
     * 
     * 性能优化：
     * - 防止单个节点累积过多日志（如10万条）
     * - 避免序列化耗时和前端渲染卡顿
     * - 告警节点优先保留所有信息
     * 
     * @param targetNode 目标节点
     * @param newLogs 要合并的新日志
     */
    private void mergeLogsWithLimit(GraphNode targetNode, List<RawLog> newLogs) {
        if (newLogs == null || newLogs.isEmpty()) {
            return;
        }
        
        // ✅ 告警节点：直接添加所有日志，不受限制
        if (targetNode.isAlarm()) {
            for (RawLog rawLog : newLogs) {
                targetNode.addLog(rawLog);
            }
            log.debug("【建图-日志累积优化】告警节点 {} 添加所有日志: {}", 
                     targetNode.getNodeId(), newLogs.size());
            return;
        }
        
        // ⚠️ 非告警节点：应用数量限制
        int currentLogCount = targetNode.getLogs().size();
        int addedCount = 0;
        int skippedCount = 0;
        
        for (RawLog rawLog : newLogs) {
            if (currentLogCount < MAX_LOGS_PER_NODE) {
                targetNode.addLog(rawLog);
                currentLogCount++;
                addedCount++;
            } else {
                skippedCount++;
                // 只在第一次达到上限时记录警告
                if (skippedCount == 1) {
                    log.warn("【建图-日志累积优化】非告警节点 {} 的日志数已达上限({}), 后续日志将被忽略", 
                             targetNode.getNodeId(), MAX_LOGS_PER_NODE);
                }
            }
        }
        
        if (skippedCount > 0) {
            log.info("【建图-日志累积优化】节点 {} 合并完成: 新增={}, 跳过={}, 当前总数={}", 
                     targetNode.getNodeId(), addedCount, skippedCount, targetNode.getLogs().size());
        }
    }
}

