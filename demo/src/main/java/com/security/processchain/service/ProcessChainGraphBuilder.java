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
            for (RawAlarm alarm : alarms) {
                if (alarm == null || alarm.getProcessGuid() == null) {
                    continue;
                }
                
                GraphNode node = createNodeFromAlarm(alarm);
                graph.addNode(node);
            }
            
            log.info("【建图】告警节点添加完成: {}", graph.getNodeCount());
        }
        
        // 阶段2：添加日志节点（只构建进程链，不拆分实体）
        if (logs != null) {
            Map<String, GraphNode> virtualParents = new HashMap<>();
            
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
                
                // 2. 处理父进程节点（如果有）
                if (parentGuid != null && !parentGuid.isEmpty()) {
                    // 检测根节点：processGuid == parentProcessGuid
                    boolean isRootNode = childGuid.equals(parentGuid);
                    
                    // ✅ 检测特殊根节点：processGuid == parentProcessGuid == traceId
                    boolean isSpecialRootNode = isRootNode && 
                                                 traceId != null && 
                                                 childGuid.equals(traceId);
                    
                    String actualParentNodeId;
                    if (isRootNode) {
                        // 根节点：为虚拟父节点生成特殊ID，避免与子节点冲突
                        actualParentNodeId = generateVirtualRootParentId(parentGuid);
                        
                        // ✅ 如果是特殊根节点，记录虚拟根父节点映射
                        if (isSpecialRootNode) {
                            graph.getVirtualRootParentMap().put(childGuid, actualParentNodeId);
                            log.info("【建图-特殊根节点】检测到 processGuid==parentProcessGuid==traceId: " +
                                    "子根节点={}, 虚拟父节点={}, traceId={}", 
                                    childGuid, actualParentNodeId, traceId);
                        }
                    } else {
                        // 非根节点：使用原始parentGuid
                        actualParentNodeId = parentGuid;
                    }
                    
                    // 创建或暂存虚拟父节点
                    if (!graph.hasNode(actualParentNodeId) && !virtualParents.containsKey(actualParentNodeId)) {
                        GraphNode virtualParent = createVirtualParentNode(rawLog, actualParentNodeId);
                        virtualParents.put(actualParentNodeId, virtualParent);
                        log.debug("【建图-父节点】暂存虚拟父节点: parentId={}, isRoot={}, isSpecial={}", 
                                actualParentNodeId, isRootNode, isSpecialRootNode);
                    }
                    
                    // 创建边：父 → 子
                    log.debug("【建图-阶段2】创建边: {} → {} (父→子)", actualParentNodeId, childGuid);
                    graph.addEdge(actualParentNodeId, childGuid);
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
                    log.debug("【建图】添加虚拟父节点: parentId={}, 日志数={}", 
                            parentId, virtualParent.getLogs().size());
                } else {
                    // 已有真实节点，合并虚拟节点的日志到真实节点
                    GraphNode realNode = graph.getNode(parentId);
                    mergeLogsWithLimit(realNode, virtualParent.getLogs());
                    replacedVirtualParentCount++;
                    log.debug("【建图】虚拟父节点被真实节点替代，已合并日志: parentId={}, 虚拟日志数={}, 真实节点总日志数={}", 
                            parentId, virtualParent.getLogs().size(), realNode.getLogs().size());
                }
            }
            
            log.info("【建图-阶段2.5】虚拟父节点处理完成: 添加={}, 替代={}", 
                    addedVirtualParentCount, replacedVirtualParentCount);
            
            log.info("【建图】日志节点添加完成: 进程节点总数={}", graph.getNodeCount());
        }
        
        // 阶段3：建立父子边（对于没有通过拆分添加边的节点）
        // 这一步主要处理告警节点的父子关系
        if (alarms != null) {
            int addedEdgeCount = 0;
            int skippedEdgeCount = 0;
            int skippedVirtualCount = 0;
            
            for (RawAlarm alarm : alarms) {
                String childGuid = alarm.getProcessGuid();
                String parentGuid = alarm.getParentProcessGuid();
                
                if (parentGuid != null && !parentGuid.isEmpty() && 
                    graph.hasNode(parentGuid) && graph.hasNode(childGuid)) {
                    
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
            
            log.info("【建图-阶段3】告警节点边处理完成: 添加={}, 跳过已存在={}, 跳过虚拟节点环={}", 
                    addedEdgeCount, skippedEdgeCount, skippedVirtualCount);
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
     * 
     * 注意：晚拆分方案中，所有节点都是进程节点（nodeType = "process"）
     * 告警的 logType 只是标记关注的行为类型，不影响节点类型
     */
    private GraphNode createNodeFromAlarm(RawAlarm alarm) {
        GraphNode node = new GraphNode();
        
        node.setNodeId(alarm.getProcessGuid());
        node.setParentProcessGuid(alarm.getParentProcessGuid());
        node.setTraceId(alarm.getTraceId());
        node.setHostAddress(alarm.getHostAddress());
        
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
        node.setParentProcessGuid(rawLog.getParentProcessGuid());
        node.setTraceId(rawLog.getTraceId());
        node.setHostAddress(rawLog.getHostAddress());
        
        // 所有节点都设置为 process 类型（实体日志也保留在进程节点上）
        node.setNodeType("process");
        
        node.addLog(rawLog);
        
        return node;
    }
    
    /**
     * 创建虚拟父进程节点
     * 
     * @param rawLog 原始日志
     * @param actualParentNodeId 实际的父节点ID（可能是原始parentGuid，也可能是生成的虚拟ID）
     * @return 虚拟父节点
     */
    private GraphNode createVirtualParentNode(RawLog rawLog, String actualParentNodeId) {
        GraphNode parentNode = new GraphNode();
        
        // 设置nodeId = 实际的父节点ID
        parentNode.setNodeId(actualParentNodeId);
        
        // 计算父进程的parentProcessGuid（hash）
        String parentParentGuid = calculateParentProcessGuidHash(rawLog);
        parentNode.setParentProcessGuid(parentParentGuid);
        
        // 标记为虚拟节点
        parentNode.setVirtual(true);
        parentNode.setNodeType("process");
        
        // 提取traceId和hostAddress
        parentNode.setTraceId(rawLog.getTraceId());
        parentNode.setHostAddress(rawLog.getHostAddress());
        
        // 创建虚拟日志（使用parent字段）
        RawLog parentLog = new RawLog();
        parentLog.setProcessGuid(actualParentNodeId);
        parentLog.setParentProcessGuid(parentParentGuid);
        parentLog.setProcessName(rawLog.getParentProcessName());
        parentLog.setImage(rawLog.getParentImage());
        parentLog.setCommandLine(rawLog.getParentCommandLine());
        parentLog.setProcessUserName(rawLog.getParentProcessUserName());
        parentLog.setProcessId(rawLog.getParentProcessId());
        parentLog.setLogType("process");
        parentLog.setOpType("create");
        parentLog.setTraceId(rawLog.getTraceId());
        parentLog.setHostAddress(rawLog.getHostAddress());
        parentLog.setStartTime(rawLog.getStartTime());
        
        // 标记为虚拟日志
        parentLog.setEventId("VIRTUAL_LOG_" + actualParentNodeId);
        
        parentNode.addLog(parentLog);
        
        return parentNode;
    }
    
    /**
     * 计算父进程的parentProcessGuid（hash）
     */
    private String calculateParentProcessGuidHash(RawLog rawLog) {
        StringBuilder sb = new StringBuilder();
        
        if (rawLog.getParentProcessName() != null) {
            sb.append(rawLog.getParentProcessName());
        }
        if (rawLog.getParentProcessUserName() != null) {
            sb.append(rawLog.getParentProcessUserName());
        }
        if (rawLog.getParentImage() != null) {
            sb.append(rawLog.getParentImage());
        }
        if (rawLog.getParentCommandLine() != null) {
            sb.append(rawLog.getParentCommandLine());
        }
        
        if (sb.length() == 0) {
            return "VIRTUAL_PARENT_" + rawLog.getParentProcessGuid();
        }
        
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(sb.toString().getBytes(StandardCharsets.UTF_8));
            return "HASH_" + bytesToHex(hash);
        } catch (Exception e) {
            return "HASH_" + Math.abs(sb.toString().hashCode());
        }
    }
    
    /**
     * 为根节点生成虚拟父节点ID
     */
    private String generateVirtualRootParentId(String originalParentGuid) {
        if (originalParentGuid == null || originalParentGuid.isEmpty()) {
            return "VIRTUAL_ROOT_PARENT_UNKNOWN";
        }
        
        String hashInput = originalParentGuid + "_ROOT_PARENT";
        String hash = calculateHash(hashInput);
        
        return "VIRTUAL_ROOT_PARENT_" + hash;
    }
    
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

