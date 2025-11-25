package com.security.processchain.service;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * 进程链图构建器（晚拆分方案）
 * 
 * 职责：
 * 1. 从原始数据（告警+日志）构建进程链图（只包含进程节点）
 * 2. 创建虚拟父进程节点（如果需要）
 * 3. 建立进程间的父子关系
 * 4. 返回完整的进程链图
 * 
 * 注意：
 * - 不再在建图阶段拆分实体节点
 * - 实体节点的提取推迟到裁剪后进行（由 EntityExtractor 负责）
 * - 日志（包括实体类型日志）都保留在进程节点上
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
            int addedCount = 0;
            int mergedCount = 0;
            // ✅ 优化：收集自引用节点告警（processGuid == parentProcessGuid）
            // 注意：这不是"真正的根节点"，只是"到头了"的节点
            List<RawAlarm> selfReferenceAlarms = new ArrayList<>();
            
            for (RawAlarm alarm : alarms) {
                if (alarm == null || alarm.getProcessGuid() == null) {
                    continue;
                }
                
                String processGuid = alarm.getProcessGuid();
                String parentProcessGuid = alarm.getParentProcessGuid();
                
                // ✅ 优化：在第一次遍历时收集自引用节点（processGuid == parentProcessGuid）
                // 这些节点需要清空 parentProcessGuid
                boolean isSelfReference = parentProcessGuid != null && processGuid.equals(parentProcessGuid);
                if (isSelfReference) {
                    selfReferenceAlarms.add(alarm);
                }
                
                if (!graph.hasNode(processGuid)) {
                    // 节点不存在，创建新节点
                    GraphNode node = createNodeFromAlarm(alarm);
                    graph.addNode(node);
                    addedCount++;
                    log.debug("【建图-告警】创建新节点: processGuid={}, logType={}", 
                            processGuid, alarm.getLogType());
                } else {
                    // 节点已存在（可能来自其他告警），合并告警
                    GraphNode existing = graph.getNode(processGuid);
                    existing.addAlarm(alarm);
                    mergedCount++;
                    log.debug("【建图-告警】合并告警到已有节点: processGuid={}, logType={}, 告警总数={}", 
                            processGuid, alarm.getLogType(), existing.getAlarms().size());
                }
            }
            
            log.info("【建图】告警节点处理完成: 新增={}, 合并={}, 图节点总数={}, 自引用节点数={}", 
                    addedCount, mergedCount, graph.getNodeCount(), selfReferenceAlarms.size());
            
            // ✅ 优化：只遍历自引用节点告警（processGuid == parentProcessGuid），而不是全部告警
            for (RawAlarm alarm : selfReferenceAlarms) {
                String processGuid = alarm.getProcessGuid();
                String traceId = alarm.getTraceId();
                
                GraphNode node = graph.getNode(processGuid);
                if (node != null) {
                    // 清空 parentProcessGuid（因为 processGuid == parentProcessGuid 是自环）
                    node.setParentProcessGuid(null);
                    // ✅ 记录自引用节点ID，用于后续根节点识别
                    graph.addSelfReferenceNodeId(processGuid);
                    log.info("【建图-阶段1】自引用节点清空 parentProcessGuid: processGuid={}, traceId={}", 
                            processGuid, traceId);
                }
            }
        }
        
        // 阶段2：添加日志节点（只构建进程链，不拆分实体）
        // ✅ 延迟拆分优化：不再在建图阶段创建虚拟父节点，推迟到子图提取后
        if (logs != null) {
            for (RawLog rawLog : logs) {
                if (rawLog == null || rawLog.getProcessGuid() == null) {
                    continue;
                }
                
                String childGuid = rawLog.getProcessGuid();
                String parentGuid = rawLog.getParentProcessGuid();
                String traceId = rawLog.getTraceId();
                
                // 1. 创建或合并子进程节点
                if (!graph.hasNode(childGuid)) {
                    // 创建新的进程节点
                    GraphNode childNode = createNodeFromLog(rawLog);
                    graph.addNode(childNode);
                } else {
                    // 节点已存在，合并日志
                    GraphNode existing = graph.getNode(childGuid);
                    mergeLogsWithLimit(existing, Collections.singletonList(rawLog));
                }
                
                // 2. 处理父进程边（如果有）
                if (parentGuid != null && !parentGuid.isEmpty()) {
                    // ✅ 跳过自引用节点（自环）
                    // 注意：如果是自引用节点，需要清空并记录
                    if (childGuid.equals(parentGuid)) {
                        GraphNode node = graph.getNode(childGuid);
                        if (node != null && node.getParentProcessGuid() != null) {
                            // 如果还没被清空（可能是纯日志节点），清空并记录
                            node.setParentProcessGuid(null);
                            graph.addSelfReferenceNodeId(childGuid);
                            log.info("【建图-阶段2】自引用节点清空 parentProcessGuid: childGuid={}, traceId={}", 
                                    childGuid, traceId);
                        } else {
                            log.info("【建图-阶段2】跳过自引用节点（自环）: childGuid={}, traceId={}", 
                                    childGuid, traceId);
                        }
                        continue;
                    }
                    
                    // ✅ 延迟拆分优化：只创建边，不创建虚拟父节点
                    // 虚拟父节点将在子图提取后创建
                    log.debug("【建图-阶段2】创建边: {} → {} (父→子)", parentGuid, childGuid);
                    graph.addEdge(parentGuid, childGuid);
                }
            }
            
            log.info("【建图】日志节点添加完成: 进程节点总数={}", graph.getNodeCount());
        }
        
        // 阶段3：建立父子边（对于没有通过拆分添加边的节点）
        // 这一步主要处理告警节点的父子关系
        if (alarms != null) {
            int addedEdgeCount = 0;
            int skippedEdgeCount = 0;
            int skippedVirtualCount = 0;
            int skippedSelfLoopCount = 0;
            
            for (RawAlarm alarm : alarms) {
                String childGuid = alarm.getProcessGuid();
                String parentGuid = alarm.getParentProcessGuid();
                
                if (parentGuid != null && !parentGuid.isEmpty() && 
                    graph.hasNode(parentGuid) && graph.hasNode(childGuid)) {
                    
                    // ✅ 跳过自环（processGuid == parentProcessGuid）
                    if (childGuid.equals(parentGuid)) {
                        skippedSelfLoopCount++;
                        // 确保记录自引用节点
                        graph.addSelfReferenceNodeId(childGuid);
                        log.info("【建图-阶段3】跳过自环: {} -> {}", parentGuid, childGuid);
                        continue;
                    }
                    
                    // ✅ 检查是否会形成环（反向边已存在）
                    if (graph.hasEdge(childGuid, parentGuid)) {
                        log.warn("【建图-阶段3】⚠️ 检测到反向边已存在，跳过以避免环路:");
                        log.warn("  - 已存在: {} → {} (子→父)", childGuid, parentGuid);
                        log.warn("  - 尝试创建: {} → {} (父→子)", parentGuid, childGuid);
                        log.warn("  - 告警信息: processGuid={}, parentProcessGuid={}", childGuid, parentGuid);
                        skippedVirtualCount++;
                        continue;
                    }
                    
                    // ✅ 检查边是否已存在（避免创建重复边）
                    if (!graph.hasEdge(parentGuid, childGuid)) {
                        log.info("【建图-阶段3】准备添加告警节点边: {} → {} (父→子)", parentGuid, childGuid);
                        graph.addEdge(parentGuid, childGuid);
                        addedEdgeCount++;
                        log.debug("【建图-阶段3】添加告警节点边完成: {} → {}", parentGuid, childGuid);
                    } else {
                        skippedEdgeCount++;
                        log.debug("【建图-阶段3】跳过已存在的边: {} → {}", parentGuid, childGuid);
                    }
                }
            }
            
            log.info("【建图-阶段3】告警节点边处理完成: 添加={}, 跳过已存在={}, 跳过虚拟节点环={}, 跳过自环={}", 
                    addedEdgeCount, skippedEdgeCount, skippedVirtualCount, skippedSelfLoopCount);
        }
        
        // 阶段4：图分析
        // ✅ 延迟拆分优化：移除建图阶段的 identifyRootNodes 调用
        // 根节点识别将在子图提取后进行（此时虚拟父节点已创建，入度计算正确）
        
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
     * 
     * 注意：晚拆分方案中，所有节点都是进程节点（nodeType = "process"）
     * 告警的 logType 只是标记关注的行为类型，不影响节点类型
     */
    private GraphNode createNodeFromAlarm(RawAlarm alarm) {
        GraphNode node = new GraphNode();
        
        node.setNodeId(alarm.getProcessGuid());
        node.setProcessGuid(alarm.getProcessGuid());
        node.setParentProcessGuid(alarm.getParentProcessGuid());
        node.setTraceId(alarm.getTraceId());
        node.setHostAddress(alarm.getHostAddress());
        node.setHostName(alarm.getHostName());
        
        // 填充进程相关字段
        node.setProcessName(alarm.getProcessName());
        node.setProcessId(alarm.getProcessId());
        node.setImage(alarm.getImage());
        node.setCommandLine(alarm.getCommandLine());
        node.setProcessMd5(alarm.getProcessMd5());
        node.setProcessUserName(alarm.getProcessUserName());
        
        // ✅ 晚拆分方案：所有节点统一设置为 "process"
        // 告警的 logType（file/domain等）保留在告警数据中
        // 实体会在裁剪后的实体提取阶段单独创建
        node.setNodeType("process");
        
        log.debug("【建图】从告警创建节点: processGuid={}, alarm.logType={}, node.nodeType=process", 
                alarm.getProcessGuid(), alarm.getLogType());
        
        node.addAlarm(alarm);
        
        return node;
    }
    
    /**
     * 从日志创建进程节点
     */
    private GraphNode createNodeFromLog(RawLog rawLog) {
        GraphNode node = new GraphNode();
        
        node.setNodeId(rawLog.getProcessGuid());
        node.setProcessGuid(rawLog.getProcessGuid());
        node.setParentProcessGuid(rawLog.getParentProcessGuid());
        node.setTraceId(rawLog.getTraceId());
        node.setHostAddress(rawLog.getHostAddress());
        node.setHostName(rawLog.getHostName());
        
        // 填充进程相关字段
        node.setProcessName(rawLog.getProcessName());
        node.setProcessId(rawLog.getProcessId());
        node.setImage(rawLog.getImage());
        node.setCommandLine(rawLog.getCommandLine());
        node.setProcessMd5(rawLog.getProcessMd5());
        node.setProcessUserName(rawLog.getProcessUserName());
        
        // 所有节点都设置为 process 类型（实体日志也保留在进程节点上）
        node.setNodeType("process");
        
        node.addLog(rawLog);
        
        return node;
    }
    
    // ✅ 延迟拆分优化：删除 createVirtualParentNode 和 calculateParentProcessGuidHash 方法
    // 虚拟父节点的创建逻辑移到 ProcessChainBuilder.createVirtualParentsForSubgraph()
    
    /**
     * 计算字符串的短hash
     */
    private String calculateHash(String str) {
        if (str == null || str.isEmpty()) {
            return "00000000";
        }
        
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(str.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 4 && i < hash.length; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return String.format("%08x", Math.abs(str.hashCode()));
        }
    }
    
    /**
     * 字节数组转十六进制字符串
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
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

