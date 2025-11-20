package com.security.processchain.util;

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
     */
    public static void extractEntitiesFromGraph(ProcessChainGraph graph) {
        if (graph == null) {
            return;
        }
        
        log.info("【实体提取】开始从进程节点提取实体，当前节点数={}", graph.getNodeCount());
        
        // 统计信息
        int totalEntityLogs = 0;
        int createdEntityNodes = 0;
        Map<String, Integer> entityTypeCount = new HashMap<>();
        
        // 收集所有要添加的实体节点和边（避免在遍历时修改图）
        List<GraphNode> entityNodesToAdd = new ArrayList<>();
        List<EdgePair> edgesToAdd = new ArrayList<>();
        
        // 1. 遍历所有节点
        for (GraphNode processNode : graph.getAllNodes()) {
            // 只处理进程节点
            if (!isProcessNode(processNode)) {
                continue;
            }
            
            String processGuid = processNode.getNodeId();
            List<RawLog> logs = processNode.getLogs();
            
            if (logs == null || logs.isEmpty()) {
                continue;
            }
            
            // 2. 从日志中提取实体
            Map<String, List<RawLog>> entityLogsByType = groupEntityLogs(logs);
            
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
                        existingNode.addLog(entityLog);
                        log.debug("【实体提取】实体节点已存在，合并日志: nodeId={}", entityNodeId);
                        continue;
                    }
                    
                    // 创建新的实体节点
                    GraphNode entityNode = createEntityNode(entityNodeId, entityType, entityLog);
                    entityNodesToAdd.add(entityNode);
                    
                    // 创建边：进程节点 → 实体节点
                    edgesToAdd.add(new EdgePair(processGuid, entityNodeId));
                    
                    createdEntityNodes++;
                    entityTypeCount.put(entityType, entityTypeCount.getOrDefault(entityType, 0) + 1);
                    
                    log.debug("【实体提取】创建实体节点: processGuid={}, entityType={}, entityNodeId={}", 
                            processGuid, entityType, entityNodeId);
                }
            }
        }
        
        // 4. 批量添加实体节点和边到图中
        for (GraphNode entityNode : entityNodesToAdd) {
            graph.addNode(entityNode);
        }
        
        for (EdgePair edge : edgesToAdd) {
            graph.addEdge(edge.getSource(), edge.getTarget());
        }
        
        log.info("【实体提取】完成: 处理实体日志={}, 创建实体节点={}, 节点总数={}", 
                totalEntityLogs, createdEntityNodes, graph.getNodeCount());
        log.info("【实体提取】各类型统计: file={}, domain={}, network={}, registry={}", 
                entityTypeCount.getOrDefault("file", 0),
                entityTypeCount.getOrDefault("domain", 0),
                entityTypeCount.getOrDefault("network", 0),
                entityTypeCount.getOrDefault("registry", 0));
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
     * @param logs 日志列表
     * @return 实体日志按类型分组的Map
     */
    private static Map<String, List<RawLog>> groupEntityLogs(List<RawLog> logs) {
        Map<String, List<RawLog>> result = new HashMap<>();
        
        for (RawLog log : logs) {
            String logType = log.getLogType();
            
            if (logType != null && ENTITY_LOG_TYPES.contains(logType.toLowerCase())) {
                String entityType = logType.toLowerCase();
                result.computeIfAbsent(entityType, k -> new ArrayList<>()).add(log);
            }
        }
        
        return result;
    }
    
    /**
     * 创建实体节点
     * 
     * @param entityNodeId 实体节点ID
     * @param entityType 实体类型（file/domain/network/registry）
     * @param entityLog 实体日志
     * @return 实体节点
     */
    private static GraphNode createEntityNode(String entityNodeId, String entityType, RawLog entityLog) {
        GraphNode node = new GraphNode();
        
        node.setNodeId(entityNodeId);
        node.setNodeType(entityType + "_entity");
        node.setTraceId(entityLog.getTraceId());
        node.setHostAddress(entityLog.getHostAddress());
        
        // 实体节点没有 parentProcessGuid
        node.setParentProcessGuid(null);
        
        // 添加日志
        node.addLog(entityLog);
        
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
}

