package com.security.processchain.util;

import com.security.processchain.model.RawLog;
import com.security.processchain.service.GraphNode;
import com.security.processchain.service.ProcessChainGraph;
import lombok.extern.slf4j.Slf4j;

import java.util.*;
import java.util.stream.Collectors;

/**
 * 实体过滤工具
 * 
 * 功能：
 * 1. 对同一processGuid的实体节点进行过滤
 * 2. 应用优先级规则和数量限制
 * 3. 去重逻辑
 * 
 * 过滤规则：
 * - file: 保留3个，优先后缀（.exe .dll .bat等），告警节点优先
 * - domain: 保留5个，最新的
 * - network: 保留5个，最新的
 * - registry: 保留3个，最早的
 * 
 * 去重规则：
 * - process: processGuid
 * - file: fileMd5 + targetFilename
 * - domain: requestDomain
 * - network: destAddress
 * - registry: targetObject
 */
@Slf4j
public class EntityFilterUtil {
    
    // 文件后缀优先级
    private static final Set<String> PRIORITY_FILE_EXTENSIONS = Set.of(
        ".exe", ".dll", ".bat", ".ps1", ".vbs", ".msi", 
        ".jsp", ".php", ".asp", ".sh", ".so"
    );
    
    /**
     * 过滤图中的实体节点
     * 
     * @param graph 进程链图
     */
    public static void filterEntityNodesInGraph(ProcessChainGraph graph) {
        if (graph == null) {
            return;
        }
        
        log.info("【实体过滤】开始过滤，当前节点数={}", graph.getNodeCount());
        
        // 1. 收集所有实体节点（按processGuid分组）
        Map<String, List<GraphNode>> entityNodesByProcess = 
                groupEntityNodesByProcess(graph);
        
        if (entityNodesByProcess.isEmpty()) {
            log.info("【实体过滤】无实体节点需要过滤");
            return;
        }
        
        // 2. 对每个processGuid的实体节点进行过滤
        Set<String> nodesToRemove = new HashSet<>();

        // generateEntityNodeId  这个函数中不同实体唯一nodeId
        // entityNodesByProcess = {
        //    "PROC_12345" -> [实体节点1, 实体节点2, 实体节点3,实体节点4, 实体节点5, 实体节点6]
        //}
        for (Map.Entry<String, List<GraphNode>> entry : 
                entityNodesByProcess.entrySet()) {
            String processGuid = entry.getKey();
            List<GraphNode> entityNodes = entry.getValue();
            
            // 按实体类型分组
            // "file" -> [实体节点1, 实体节点2, 实体节点3] "domain" -> [实体节点4, 实体节点5, 实体节点6]
            Map<String, List<GraphNode>> byType = groupByEntityType(entityNodes);
            
            // 对每种类型应用过滤规则
            for (Map.Entry<String, List<GraphNode>> typeEntry : 
                    byType.entrySet()) {
                String entityType = typeEntry.getKey();
                List<GraphNode> nodesOfType = typeEntry.getValue();
                
                // 去重
                List<GraphNode> uniqueNodes = 
                        deduplicateNodes(nodesOfType, entityType);
                
                // 应用过滤规则，去除不必要的实体节点，防止过多
                List<GraphNode> filtered = 
                        applyFilterRules(entityType, uniqueNodes);
                
                // 标记要移除的节点
                for (GraphNode node : uniqueNodes) {
                    if (!filtered.contains(node)) {
                        nodesToRemove.add(node.getNodeId());
                    }
                }
                
                log.debug("【实体过滤】processGuid={}, type={}, 原数量={}, 去重后={}, 过滤后={}", 
                        processGuid, entityType, nodesOfType.size(), 
                        uniqueNodes.size(), filtered.size());
            }
        }
        
        // 3. 移除节点
        for (String nodeId : nodesToRemove) {
            graph.removeCutNode(nodeId);
        }
        
        log.info("【实体过滤】过滤完成，移除 {} 个实体节点，剩余节点数={}", 
                nodesToRemove.size(), graph.getNodeCount());
    }
    
    /**
     * 按processGuid分组实体节点
     */
    private static Map<String, List<GraphNode>> groupEntityNodesByProcess(
            ProcessChainGraph graph) {
        Map<String, List<GraphNode>> result = new HashMap<>();
        
        for (GraphNode node : graph.getAllNodes()) {
            // 只处理实体节点
            if (!isEntityNode(node)) {
                continue;
            }
            
            // 获取该实体节点关联的process节点
            String processGuid = findProcessGuidForEntityNode(graph, node);
            
            if (processGuid != null) {
                result.computeIfAbsent(processGuid, k -> new ArrayList<>())
                      .add(node);
            }
        }
        
        return result;
    }
    
    /**
     * 查找实体节点关联的processGuid
     * （实体节点的父节点就是process节点）
     */
    private static String findProcessGuidForEntityNode(
            ProcessChainGraph graph, 
            GraphNode entityNode) {
        // 获取父节点
        List<String> parents = graph.getParents(entityNode.getNodeId());
        
        if (!parents.isEmpty()) {
            // 第一个父节点就是process节点
            return parents.get(0);
        }
        
        // 如果没有父节点，尝试从nodeId提取
        String nodeId = entityNode.getNodeId();
        if (nodeId != null && nodeId.contains("_")) {
            return nodeId.substring(0, nodeId.indexOf("_"));
        }
        
        return null;
    }
    
    /**
     * 判断是否是实体节点
     */
    private static boolean isEntityNode(GraphNode node) {
        if (node == null || node.getNodeType() == null) {
            return false;
        }
        
        String type = node.getNodeType().toLowerCase();
        return type.contains("file") || 
               type.contains("domain") || 
               type.contains("network") || 
               type.contains("registry") ||
               type.equals("file_entity") ||
               type.equals("domain_entity") ||
               type.equals("network_entity") ||
               type.equals("registry_entity");//
    }
    
    /**
     * 按实体类型分组
     */
    private static Map<String, List<GraphNode>> groupByEntityType(
            List<GraphNode> nodes) {
        Map<String, List<GraphNode>> result = new HashMap<>();
        
        for (GraphNode node : nodes) {
            String type = extractEntityType(node);
            result.computeIfAbsent(type, k -> new ArrayList<>())
                  .add(node);
        }
        
        return result;
    }
    
    /**
     * 提取实体类型
     */
    private static String extractEntityType(GraphNode node) {
        String nodeId = node.getNodeId();
        
        if (nodeId == null) {
            return "unknown";
        }
        
        if (nodeId.contains("_FILE_")) return "file";
        if (nodeId.contains("_DOMAIN_")) return "domain";
        if (nodeId.contains("_NETWORK_")) return "network";
        if (nodeId.contains("_REGISTRY_")) return "registry";
        
        return "unknown";
    }
    
    /**
     * 去重
     * 
     * 注意：实际上在 EntityExtractor.extractEntitiesFromGraph 中已经做了去重
     * （通过 graph.hasNode(entityNodeId) 检查并合并日志/告警）
     * 
     * 这里的去重是兜底保护，理论上不应该有重复节点。
     * 直接使用 nodeId 作为唯一键即可，因为 nodeId 生成时已经基于
     * 相同的字段（fileMd5+filename、requestDomain 等）进行了哈希。
     */
    private static List<GraphNode> deduplicateNodes(
            List<GraphNode> nodes, 
            String entityType) {
        Map<String, GraphNode> uniqueMap = new LinkedHashMap<>();
        
        for (GraphNode node : nodes) {
            // ✅ 直接使用 nodeId 作为唯一键
            // nodeId 已经包含了唯一性信息（如 PROC_12345_FILE_hash123）
            String nodeId = node.getNodeId();
            
            if (!uniqueMap.containsKey(nodeId)) {
                uniqueMap.put(nodeId, node);
            } else {
                // ⚠️ 理论上不应该走到这里，因为 EntityExtractor 已经去重了
                log.warn("【实体去重】发现重复的实体节点: nodeId={}, entityType={}", 
                        nodeId, entityType);
            }
        }
        
        return new ArrayList<>(uniqueMap.values());
    }
    
    /**
     * 应用过滤规则
     */
    private static List<GraphNode> applyFilterRules(
            String entityType, 
            List<GraphNode> nodes) {
        
        switch (entityType.toLowerCase()) {
            case "file":
                return filterFileNodes(nodes, 3);
                
            case "domain":
                return filterDomainNodes(nodes, 5);
                
            case "network":
                return filterNetworkNodes(nodes, 5);
                
            case "registry":
                return filterRegistryNodes(nodes, 3);
                
            default:
                return nodes;
        }
    }
    
    /**
     * 过滤file节点
     * 规则：
     * 1. 优先后缀（.exe .dll等）+ opType=create → 全部保留
     * 2. 非优先后缀的文件：
     *    - create 操作：保留最早的 3 个
     *    - write 操作：保留最早的 3 个
     *    - delete 操作：保留最早的 3 个
     */
    private static List<GraphNode> filterFileNodes(
            List<GraphNode> nodes, int limit) {
        
        // 1. 分类：优先文件（优先后缀+create） vs 普通文件（按opType分组）
        List<GraphNode> priorityFiles = new ArrayList<>();
        Map<String, List<GraphNode>> normalFilesByOpType = new HashMap<>();
        
        for (GraphNode node : nodes) {
            String filename = extractFilename(node);
            String opType = extractOpType(node);
            
            // 判断是否有优先后缀
            boolean hasPriorityExt = hasPriorityExtension(filename);
            
            // 优先后缀 + opType=create → 全部保留
            if (hasPriorityExt && "create".equalsIgnoreCase(opType)) {
                priorityFiles.add(node);
            } else {
                // 非优先后缀的文件，按 opType 分组
                String opTypeKey = (opType == null || opType.isEmpty()) ? "unknown" : opType.toLowerCase();
                normalFilesByOpType.computeIfAbsent(opTypeKey, k -> new ArrayList<>()).add(node);
            }
        }
        
        log.debug("【文件过滤】优先文件(优先后缀+create)数={}, 普通文件分组={}", 
                priorityFiles.size(), normalFilesByOpType.keySet());
        
        // 2. 优先文件全部保留
        List<GraphNode> result = new ArrayList<>(priorityFiles);
        
        // 3. 普通文件按 opType 分组，每组保留最早的 3 个
        int totalNormalFiles = 0;
        for (Map.Entry<String, List<GraphNode>> entry : normalFilesByOpType.entrySet()) {
            String opType = entry.getKey();
            List<GraphNode> filesOfType = entry.getValue();
            
            // 按时间升序排序（最早的在前）
            filesOfType.sort((a, b) -> compareByTime(a, b, true));
            
            // 取前 3 个
            int count = Math.min(limit, filesOfType.size());
            result.addAll(filesOfType.subList(0, count));
            totalNormalFiles += count;
            
            log.debug("【文件过滤】普通文件 opType={}, 总数={}, 保留最早的{}个", 
                    opType, filesOfType.size(), count);
        }
        
        log.debug("【文件过滤】最终保留文件数={} (优先{}个 + 普通{}个)", 
                result.size(), priorityFiles.size(), totalNormalFiles);
        
        return result;
    }
    
    /**
     * 过滤domain节点
     * 规则：保留最早的5个
     */
    private static List<GraphNode> filterDomainNodes(
            List<GraphNode> nodes, int limit) {
        
        if (nodes.size() <= limit) {
            return nodes;
        }
        
        // ✅ 修改：按时间升序排序（最早的在前）
        nodes.sort((a, b) -> compareByTime(a, b, true));
        
        return nodes.stream()
                .limit(limit)
                .collect(Collectors.toList());
    }
    
    /**
     * 过滤network节点
     * 规则：保留最早的5个
     */
    private static List<GraphNode> filterNetworkNodes(
            List<GraphNode> nodes, int limit) {
        
        if (nodes.size() <= limit) {
            return nodes;
        }
        
        // ✅ 修改：与domain相同，保留最早的
        nodes.sort((a, b) -> compareByTime(a, b, true));
        
        return nodes.stream()
                .limit(limit)
                .collect(Collectors.toList());
    }
    
    /**
     * 过滤registry节点
     * 规则：保留最早的3个
     */
    private static List<GraphNode> filterRegistryNodes(
            List<GraphNode> nodes, int limit) {
        
        if (nodes.size() <= limit) {
            return nodes;
        }
        
        // 按时间升序排序（最早的在前）
        nodes.sort((a, b) -> compareByTime(a, b, true));
        
        return nodes.stream()
                .limit(limit)
                .collect(Collectors.toList());
    }
    
    /**
     * 比较节点时间
     * 
     * @param ascending true=升序（早的在前），false=降序（新的在前）
     */
    private static int compareByTime(
            GraphNode a, 
            GraphNode b, 
            boolean ascending) {
        String timeA = extractStartTime(a);
        String timeB = extractStartTime(b);
        
        if (timeA == null && timeB == null) return 0;
        if (timeA == null) return 1;
        if (timeB == null) return -1;
        
        int cmp = timeA.compareTo(timeB);
        return ascending ? cmp : -cmp;
    }
    
    /**
     * 提取文件名
     * 
     * 优先级：
     * 1. 优先从日志中提取
     * 2. 如果没有日志，从告警中提取
     */
    private static String extractFilename(GraphNode node) {
        // 1. 优先从日志中提取
        if (node.getLogs() != null && !node.getLogs().isEmpty()) {
            RawLog log = node.getLogs().get(0);
            String filename = log.getTargetFilename();
            
            if (filename == null || filename.isEmpty()) {
                filename = log.getFileName();
            }
            
            if (filename != null && !filename.isEmpty()) {
                return filename;
            }
        }
        
        // 2. 如果没有日志，从告警中提取
        if (node.getAlarms() != null && !node.getAlarms().isEmpty()) {
            String filename = node.getAlarms().get(0).getTargetFilename();
            
            if (filename == null || filename.isEmpty()) {
                filename = node.getAlarms().get(0).getFileName();
            }
            
            return filename != null ? filename : "";
        }
        
        return "";
    }
    
    /**
     * 提取opType
     * 
     * 优先级：
     * 1. 优先从日志中提取
     * 2. 如果没有日志，从告警中提取
     */
    private static String extractOpType(GraphNode node) {
        // 1. 优先从日志中提取
        if (node.getLogs() != null && !node.getLogs().isEmpty()) {
            RawLog log = node.getLogs().get(0);
            String opType = log.getOpType();
            if (opType != null && !opType.isEmpty()) {
                return opType;
            }
        }
        
        // 2. 如果没有日志，从告警中提取
        if (node.getAlarms() != null && !node.getAlarms().isEmpty()) {
            String opType = node.getAlarms().get(0).getOpType();
            return opType != null ? opType : "";
        }
        
        return "";
    }
    
    /**
     * 提取开始时间
     * 
     * 优先级：
     * 1. 优先从日志中提取（logs 优先于 alarms）
     * 2. 如果没有日志，从告警中提取
     */
    private static String extractStartTime(GraphNode node) {
        // 1. 优先从日志中提取
        if (node.getLogs() != null && !node.getLogs().isEmpty()) {
            RawLog log = node.getLogs().get(0);
            String startTime = log.getStartTime();
            if (startTime != null && !startTime.isEmpty()) {
                return startTime;
            }
        }
        
        // 2. 如果没有日志，从告警中提取
        if (node.getAlarms() != null && !node.getAlarms().isEmpty()) {
            return node.getAlarms().get(0).getStartTime();
        }
        
        return null;
    }
    
    /**
     * 判断文件是否有优先后缀
     */
    private static boolean hasPriorityExtension(String filename) {
        if (filename == null || filename.isEmpty()) {
            return false;
        }
        
        String lower = filename.toLowerCase();
        return PRIORITY_FILE_EXTENSIONS.stream()
                .anyMatch(ext -> lower.endsWith(ext));
    }
}

