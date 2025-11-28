package com.security.processchain.util;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.GraphNode;
import com.security.processchain.service.ProcessChainGraph;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/**
 * 实体提取器（晚拆分方案）
 * 
 * 职责：
 * 1. 在进程链裁剪完成后，从保留的进程节点中提取实体节点
 * 2. 创建进程节点 → 实体节点的边关系
 * 3. 应用实体过滤规则
 * 
 * 优势：
 * - 避免实体节点断链（实体节点的父进程节点一定存在）
 * - 提高建图性能（初期节点数更少）
 * - 裁剪更精准（只基于进程关系裁剪）
 * 
 * 实体类型：
 * - file: 文件操作
 * - domain: 域名请求
 * - network: 网络连接
 * - registry: 注册表操作
 */
@Slf4j
public class EntityExtractor {
    
    // 实体类型日志
    private static final Set<String> ENTITY_LOG_TYPES = Set.of(
        "file", "domain", "network", "registry"
    );
    
    /**
     * 从图中的进程节点提取实体节点
     * 
     * 流程：
     * 1. 遍历图中所有进程节点
     * 2. 从进程节点的日志中识别实体日志（file/domain/network/registry）
     * 3. 为每个实体日志创建实体节点
     * 4. 建立进程节点 → 实体节点的边
     * 5. 应用实体过滤规则
     * 
     * @param graph 进程链图（只包含进程节点）
     * @param networkAssociatedEventIds 网端关联的事件ID（告警+日志），用于优先设置 createdByEventId
     */
    public static void extractEntitiesFromGraph(ProcessChainGraph graph, Set<String> networkAssociatedEventIds) {
        if (graph == null) {
            return;
        }
        
        log.info("【实体提取】开始从进程节点提取实体，当前节点数={}", graph.getNodeCount());
        
        // 统计信息
        int totalEntityLogs = 0;
        int createdEntityNodes = 0;
        int processNodeCount = 0;
        int totalLogs = 0;
        Map<String, Integer> entityTypeCount = new HashMap<>();
        Map<String, Integer> allLogTypeCount = new HashMap<>();
        
        // 收集所有要添加的实体节点和边信息（避免在遍历时修改图）
        List<GraphNode> entityNodesToAdd = new ArrayList<>();
        Map<String, String> entityToProcessMap = new HashMap<>();  // entityNodeId -> processGuid
        
        // 1. 遍历所有节点
        for (GraphNode node : graph.getAllNodes()) {
            // 统计所有节点的类型
            String nodeType = node.getNodeType();
            log.debug("【实体提取-调试】节点: id={}, nodeType={}, isVirtual={}, 日志数={}", 
                    node.getNodeId(), nodeType, node.isVirtual(), 
                    node.getLogs() != null ? node.getLogs().size() : 0);
            
            // ✅ 跳过虚拟节点（虚拟父节点不应该提取实体）
            if (node.isVirtual()) {
                log.debug("【实体提取-调试】跳过虚拟节点: id={}, nodeType={}", 
                        node.getNodeId(), nodeType);
                continue;
            }
            
            // 只处理进程节点
            if (!isProcessNode(node)) {
                log.debug("【实体提取-调试】跳过非进程节点: id={}, nodeType={}", 
                        node.getNodeId(), nodeType);
                continue;
            }
            
            processNodeCount++;
            String processGuid = node.getNodeId();
            
            // ✅ 优先从日志中提取实体（节点级优先级）
            List<RawLog> logs = node.getLogs();
            if (logs != null && !logs.isEmpty()) {
                totalLogs += logs.size();
                
                // 统计日志类型
                for (RawLog rawLog : logs) {
                    String logType = rawLog.getLogType();
                    allLogTypeCount.put(logType != null ? logType : "null", 
                            allLogTypeCount.getOrDefault(logType != null ? logType : "null", 0) + 1);
                }
                
                // 2. 从日志中提取实体
                Map<String, List<RawLog>> entityLogsByType = groupEntityLogs(logs);
                
                if (!entityLogsByType.isEmpty()) {
                    log.info("【实体提取】进程节点 {} 包含实体日志: {}", processGuid, entityLogsByType.keySet());
                }
                
                for (Map.Entry<String, List<RawLog>> entry : entityLogsByType.entrySet()) {
                    String entityType = entry.getKey();
                    List<RawLog> entityLogs = entry.getValue();
                    
                    totalEntityLogs += entityLogs.size();
                    
                    // 3. 为每个实体日志创建实体节点
                    for (RawLog entityLog : entityLogs) {
                        String entityNodeId = generateEntityNodeId(processGuid, entityLog);
                        
                        // 检查节点是否已存在（去重）
                        if (graph.hasNode(entityNodeId)) {
                            // 节点已存在，合并日志
                            GraphNode existingNode = graph.getNode(entityNodeId);
                            existingNode.addLog(entityLog);// 日志从进程节点"移动"到实体节点
                            
                            // ✅ 如果当前日志是网端关联的，更新 createdByEventId（高优先级）
                            if (networkAssociatedEventIds != null && 
                                entityLog.getEventId() != null &&
                                networkAssociatedEventIds.contains(entityLog.getEventId())) {
                                existingNode.setCreatedByEventId(entityLog.getEventId());
                                log.info("【实体提取】更新实体节点为网端关联（日志）: nodeId={}, eventId={}", 
                                        entityNodeId, entityLog.getEventId());
                            }
                            
                            log.debug("【实体提取】实体节点已存在，合并日志: nodeId={}", entityNodeId);
                            continue;
                        }
                        
                        // 创建新的实体节点（同时继承父进程节点的告警）
                        GraphNode entityNode = createEntityNode(entityNodeId, entityType, entityLog, node);
                        entityNodesToAdd.add(entityNode);
                        entityToProcessMap.put(entityNodeId, processGuid);  // ✅ 记录映射关系
                        
                        createdEntityNodes++;
                        entityTypeCount.put(entityType, entityTypeCount.getOrDefault(entityType, 0) + 1);
                        
                        log.info("【实体提取】创建实体节点: processGuid={}, entityType={}, entityNodeId={}", 
                                processGuid, entityType, entityNodeId);
                    }
                }
                
                continue;  // ✅ 节点级优先级：有日志就不处理告警
            }
            
            // ✅ 新增：没有日志时，从告警中提取实体
            List<RawAlarm> alarms = node.getAlarms();
            if (alarms != null && !alarms.isEmpty()) {
                log.debug("【实体提取-告警】进程节点 {} 没有日志，尝试从 {} 条告警中提取实体", 
                        processGuid, alarms.size());
                
                // 2. 从告警中提取实体
                for (RawAlarm alarm : alarms) {
                    String entityType = determineEntityTypeFromAlarm(alarm);
                    
                    if (!isEntityType(entityType)) {
                        continue;  // 不是实体类型（process），跳过
                    }
                    
                    totalEntityLogs++;
                    
                    // 3. 为每个实体告警创建实体节点id
                    String entityNodeId = generateEntityNodeIdFromAlarm(processGuid, alarm, entityType);
                    
                    // 检查节点是否已存在（去重）
                    if (graph.hasNode(entityNodeId)) {
                        // 节点已存在，合并告警
                        GraphNode existingNode = graph.getNode(entityNodeId);
                        existingNode.addAlarm(alarm);
                        
                        // ✅ 如果当前告警是网端关联的，更新 createdByEventId（高优先级）
                        if (networkAssociatedEventIds != null && 
                            alarm.getEventId() != null &&
                            networkAssociatedEventIds.contains(alarm.getEventId())) {
                            existingNode.setCreatedByEventId(alarm.getEventId());
                            log.info("【实体提取】更新实体节点为网端关联（告警）: nodeId={}, eventId={}", 
                                    entityNodeId, alarm.getEventId());
                        }
                        
                        log.debug("【实体提取-告警】实体节点已存在，合并告警: nodeId={}", entityNodeId);
                        continue;
                    }
                    
                    // 创建新的实体节点（同时继承父进程节点的告警）
                    GraphNode entityNode = createEntityNodeFromAlarm(entityNodeId, entityType, alarm, node);
                    entityNodesToAdd.add(entityNode);
                    entityToProcessMap.put(entityNodeId, processGuid);  // ✅ 记录映射关系
                    
                    createdEntityNodes++;
                    entityTypeCount.put(entityType, entityTypeCount.getOrDefault(entityType, 0) + 1);
                    
                    log.info("【实体提取-告警】创建实体节点: processGuid={}, entityType={}, entityNodeId={}", 
                            processGuid, entityType, entityNodeId);
                }
            }
        }
        
        // 4. 批量添加实体节点和边到图中
        for (GraphNode entityNode : entityNodesToAdd) {
            graph.addNode(entityNode);
        }
        
        // ✅ 批量创建边：进程节点 → 实体节点，val="连接"
        for (Map.Entry<String, String> entry : entityToProcessMap.entrySet()) {
            String entityNodeId = entry.getKey();
            String processGuid = entry.getValue();
            
            if (graph.hasNode(processGuid) && graph.hasNode(entityNodeId)) {
                graph.addEdge(processGuid, entityNodeId, "连接");
                log.debug("【实体提取】创建实体边: {} → {}, val=连接", processGuid, entityNodeId);
            } else {
                log.warn("【实体提取】⚠️ 无法创建实体边（节点不存在）: processGuid={}, entityNodeId={}", 
                        processGuid, entityNodeId);
            }
        }
        
        log.info("【实体提取】统计信息:");
        log.info("  - 进程节点数: {}", processNodeCount);
        log.info("  - 总日志数: {}", totalLogs);
        log.info("  - 日志类型分布: {}", allLogTypeCount);
        log.info("  - 实体日志数: {}", totalEntityLogs);
        log.info("  - 创建实体节点数: {}", createdEntityNodes);
        log.info("  - 图节点总数: {}", graph.getNodeCount());
        log.info("【实体提取】各类型统计: file={}, domain={}, network={}, registry={}", 
                entityTypeCount.getOrDefault("file", 0),
                entityTypeCount.getOrDefault("domain", 0),
                entityTypeCount.getOrDefault("network", 0),
                entityTypeCount.getOrDefault("registry", 0));
        
        if (createdEntityNodes == 0 && totalLogs > 0) {
            log.warn("【实体提取】⚠️ 警告: 有日志但没有创建实体节点！");
            log.warn("  可能原因: 1) 所有日志的logType都是'process' 2) logType不匹配 (file/domain/network/registry)");
        }
    }
    
    /**
     * 判断是否是进程节点
     */
    private static boolean isProcessNode(GraphNode node) {
        if (node == null || node.getNodeType() == null) {
            return false;
        }
        
        String nodeType = node.getNodeType().toLowerCase();
        return "process".equals(nodeType);
    }
    
    /**
     * 从日志列表中提取实体日志，按类型分组
     * 
     * 验证条件（同 IncidentConverters）：
     * - file: logType=file 且 opType=create/write/delete
     * - network: logType=network 且 opType=connect
     * - domain: logType=domain 且 opType=connect
     * - registry: logType=registry 且 opType=setValue
     * 
     * @param logs 日志列表
     * @return 实体日志按类型分组的Map
     */
    private static Map<String, List<RawLog>> groupEntityLogs(List<RawLog> logs) {
        Map<String, List<RawLog>> result = new HashMap<>();
        int skippedCount = 0;
        
        for (RawLog log : logs) {
            String logType = log.getLogType();
            String opType = log.getOpType();
            
            if (logType == null || opType == null) {
                continue;
            }
            
            String logTypeLower = logType.toLowerCase();
            String opTypeLower = opType.toLowerCase();
            
            // 检查是否是实体类型
            if (!ENTITY_LOG_TYPES.contains(logTypeLower)) {
                continue;
            }
            
            // ✅ 根据实体类型验证 opType（与 IncidentConverters 保持一致）
            boolean isValid = false;
            
            switch (logTypeLower) {
                case "file":
                    // file 实体：opType 必须是 create/write/delete
                    isValid = "create".equals(opTypeLower) || 
                             "write".equals(opTypeLower) || 
                             "delete".equals(opTypeLower);
                    break;
                    
                case "network":
                    // network 实体：opType 必须是 connect
                    isValid = "connect".equals(opTypeLower);
                    break;
                    
                case "domain":
                    // domain 实体：opType 必须是 connect
                    isValid = "connect".equals(opTypeLower);
                    break;
                    
                case "registry":
                    // registry 实体：opType 必须是 setValue
                    isValid = "setvalue".equals(opTypeLower);
                    break;
                    
                default:
                    isValid = false;
            }
            
            if (isValid) {
                result.computeIfAbsent(logTypeLower, k -> new ArrayList<>()).add(log);
            } else {
                skippedCount++;
            }
        }
        
        if (skippedCount > 0) {
            log.debug("【实体提取-日志筛选】因 opType 不匹配跳过 {} 条日志", skippedCount);
        }
        
        return result;
    }
    
    /**
     * 创建实体节点
     * 
     * @param entityNodeId 实体节点ID
     * @param entityType 实体类型（file/domain/network/registry）
     * @param entityLog 实体日志
     * @param parentProcessNode 父进程节点（用于继承告警信息）
     * @return 实体节点
     */
    private static GraphNode createEntityNode(String entityNodeId, String entityType, RawLog entityLog, GraphNode parentProcessNode) {
        GraphNode node = new GraphNode();
        
        node.setNodeId(entityNodeId);
        node.setNodeType(entityType + "_entity");
        node.setTraceId(entityLog.getTraceId());
        node.setHostAddress(entityLog.getHostAddress());
        node.setVirtual(false);  // ✅ 明确标记为非虚拟节点
        
        // 实体节点没有 processGuid 和 parentProcessGuid
        // 它们通过边（process → entity）与进程节点关联
        node.setProcessGuid(null);
        node.setParentProcessGuid(null);
        
        // ✅ 记录创建该实体的日志 eventId（用于网端关联精确匹配）
        node.setCreatedByEventId(entityLog.getEventId());
        
        // 添加日志
        node.addLog(entityLog);
        
        // ✅ 继承父进程节点的告警（用于网端关联标识）
        if (parentProcessNode != null) {
            List<RawAlarm> parentAlarms = parentProcessNode.getAlarms();
            if (parentAlarms != null && !parentAlarms.isEmpty()) {
                for (RawAlarm alarm : parentAlarms) {
                    node.addAlarm(alarm);
                }
                log.debug("【实体提取】实体节点继承 {} 条父进程告警: entityNodeId={}", 
                        parentAlarms.size(), entityNodeId);
            }
        }
        
        return node;
    }
    
    /**
     * 生成实体节点ID
     * 
     * 格式：processGuid + "_" + 类型 + "_" + hash(唯一标识)
     * 
     * 去重规则：
     * - file: fileMd5 + targetFilename
     * - domain: requestDomain
     * - network: destAddress
     * - registry: targetObject
     */
    private static String generateEntityNodeId(String processGuid, RawLog rawLog) {
        String logType = rawLog.getLogType().toLowerCase();
        
        switch (logType) {
            case "file":
                String fileMd5 = rawLog.getFileMd5() != null ? rawLog.getFileMd5() : "NOMD5";
                String filename = rawLog.getTargetFilename() != null ? rawLog.getTargetFilename() : "NONAME";
                String fileKey = fileMd5 + "_" + filename;
                String fileHash = calculateHash(fileKey);
                return processGuid + "_FILE_" + fileHash;
                
            case "domain":
                String domain = rawLog.getRequestDomain() != null ? rawLog.getRequestDomain() : "NODOMAIN";
                String domainHash = calculateHash(domain);
                return processGuid + "_DOMAIN_" + domainHash;
                
            case "network":
                String destAddr = rawLog.getDestAddress() != null ? rawLog.getDestAddress() : "NOADDR";
                String networkHash = calculateHash(destAddr);
                return processGuid + "_NETWORK_" + networkHash;
                
            case "registry":
                String targetObj = rawLog.getTargetObject() != null ? rawLog.getTargetObject() : "NOOBJ";
                String regHash = calculateHash(targetObj);
                return processGuid + "_REGISTRY_" + regHash;
                
            default:
                return processGuid + "_ENTITY_" + Math.abs(logType.hashCode());
        }
    }
    
    /**
     * 计算字符串的短hash（使用MD5的前8位）
     * 
     * @param str 输入字符串
     * @return 8位十六进制hash值
     */
    private static String calculateHash(String str) {
        if (str == null || str.isEmpty()) {
            return "00000000";
        }
        
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(str.getBytes(StandardCharsets.UTF_8));
            // 只取前4个字节（8位十六进制）
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 4 && i < hash.length; i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            // 降级方案：使用Java hashCode
            return String.format("%08x", Math.abs(str.hashCode()));
        }
    }
    
    /**
     * 判断告警的实体类型（根据字段，不是logType）
     * 
     * 规则（只判断字段是否存在）：
     * - file: fileMd5 + targetFilename 存在，且 targetFilename != image
     * - domain: requestDomain 存在
     * - network: destAddress 存在，且 != hostAddress
     * - registry: targetObject 存在
     * - process: 其他情况
     * 
     * 注意：此方法不验证 opType，opType 由 IncidentConverters 在转换时统一强制设定
     */
    private static String determineEntityTypeFromAlarm(RawAlarm alarm) {
        // 1. 文件实体：只判断字段是否存在
        if (alarm.getFileMd5() != null && !alarm.getFileMd5().isEmpty() &&
            alarm.getTargetFilename() != null && !alarm.getTargetFilename().isEmpty() &&
            !alarm.getTargetFilename().equals(alarm.getImage())) {
            return "file";
        }
        
        // 2. 域名实体：只判断字段是否存在
        if (alarm.getRequestDomain() != null && !alarm.getRequestDomain().isEmpty()) {
            return "domain";
        }
        
        // 3. 网络实体：只判断字段是否存在（排除本机地址）
        if (alarm.getDestAddress() != null && !alarm.getDestAddress().isEmpty() &&
            !alarm.getDestAddress().equals(alarm.getHostAddress())) {
            return "network";
        }
        
        // 4. 注册表实体：只判断字段是否存在
        if (alarm.getTargetObject() != null && !alarm.getTargetObject().isEmpty()) {
            return "registry";
        }
        
        // 5. 其他：进程创建
        return "process";
    }
    
    /**
     * 判断是否是实体类型
     */
    private static boolean isEntityType(String entityType) {
        return "file".equals(entityType) || 
               "domain".equals(entityType) || 
               "network".equals(entityType) || 
               "registry".equals(entityType);
    }
    
    /**
     * 从告警生成实体节点ID
     */
    private static String generateEntityNodeIdFromAlarm(String processGuid, RawAlarm alarm, String entityType) {
        switch (entityType) {
            case "file":
                String fileMd5 = alarm.getFileMd5() != null ? alarm.getFileMd5() : "NOMD5";
                String filename = alarm.getTargetFilename() != null ? alarm.getTargetFilename() : "NONAME";
                String fileKey = fileMd5 + "_" + filename;
                String fileHash = calculateHash(fileKey);
                return processGuid + "_FILE_" + fileHash;
                
            case "domain":
                String domain = alarm.getRequestDomain() != null ? alarm.getRequestDomain() : "NODOMAIN";
                String domainHash = calculateHash(domain);
                return processGuid + "_DOMAIN_" + domainHash;
                
            case "network":
                String destAddr = alarm.getDestAddress() != null ? alarm.getDestAddress() : "NOADDR";
                String networkHash = calculateHash(destAddr);
                return processGuid + "_NETWORK_" + networkHash;
                
            case "registry":
                String targetObj = alarm.getTargetObject() != null ? alarm.getTargetObject() : "NOOBJ";
                String regHash = calculateHash(targetObj);
                return processGuid + "_REGISTRY_" + regHash;
                
            default:
                return processGuid + "_ENTITY_" + calculateHash(alarm.getEventId());
        }
    }
    
    /**
     * 从告警创建实体节点
     */
    private static GraphNode createEntityNodeFromAlarm(String entityNodeId, String entityType, RawAlarm alarm, GraphNode parentProcessNode) {
        GraphNode entityNode = new GraphNode();
        
        entityNode.setNodeId(entityNodeId);
        entityNode.setNodeType(entityType + "_entity");  // ✅ 与 createEntityNode 保持一致
        entityNode.setTraceId(alarm.getTraceId());
        entityNode.setHostAddress(alarm.getHostAddress());
        entityNode.setVirtual(false);
        
        // 实体节点没有 processGuid 和 parentProcessGuid
        // 它们通过边（process → entity）与进程节点关联
        entityNode.setProcessGuid(null);
        entityNode.setParentProcessGuid(null);
        
        // ✅ 记录创建该实体的告警 eventId（用于网端关联精确匹配）
        entityNode.setCreatedByEventId(alarm.getEventId());
        
        // 添加告警到节点
        entityNode.addAlarm(alarm);
        
        // ✅ 继承父进程节点的告警（用于网端关联标识）
        if (parentProcessNode != null) {
            List<RawAlarm> parentAlarms = parentProcessNode.getAlarms();
            if (parentAlarms != null && !parentAlarms.isEmpty()) {
                for (RawAlarm parentAlarm : parentAlarms) {
                    // 避免重复添加（当前告警已经添加过了）
                    if (!parentAlarm.getEventId().equals(alarm.getEventId())) {
                        entityNode.addAlarm(parentAlarm);
                    }
                }
                log.debug("【实体提取-告警】实体节点继承 {} 条父进程告警: entityNodeId={}", 
                        parentAlarms.size(), entityNodeId);
            }
        }
        
        return entityNode;
    }
}

