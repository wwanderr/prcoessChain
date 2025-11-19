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
        
        for (Map.Entry<String, List<GraphNode>> entry : 
                entityNodesByProcess.entrySet()) {
            String processGuid = entry.getKey();
            List<GraphNode> entityNodes = entry.getValue();
            
            // 按实体类型分组
            Map<String, List<GraphNode>> byType = 
                    groupByEntityType(entityNodes);
            
            // 对每种类型应用过滤规则
            for (Map.Entry<String, List<GraphNode>> typeEntry : 
                    byType.entrySet()) {
                String entityType = typeEntry.getKey();
                List<GraphNode> nodesOfType = typeEntry.getValue();
                
                // 去重
                List<GraphNode> uniqueNodes = 
                        deduplicateNodes(nodesOfType, entityType);
                
                // 应用过滤规则
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
            graph.removeNode(nodeId);
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
               type.equals("registry_entity");
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
     */
    private static List<GraphNode> deduplicateNodes(
            List<GraphNode> nodes, 
            String entityType) {
        Map<String, GraphNode> uniqueMap = new LinkedHashMap<>();
        
        for (GraphNode node : nodes) {
            String uniqueKey = generateUniqueKey(node, entityType);
            
            // 如果已存在，比较优先级（告警节点优先）
            if (uniqueMap.containsKey(uniqueKey)) {
                GraphNode existing = uniqueMap.get(uniqueKey);
                if (node.isAlarm() && !existing.isAlarm()) {
                    uniqueMap.put(uniqueKey, node);  // 替换为告警节点
                }
            } else {
                uniqueMap.put(uniqueKey, node);
            }
        }
        
        return new ArrayList<>(uniqueMap.values());
    }
    
    /**
     * 生成唯一键（用于去重）
     */
    private static String generateUniqueKey(
            GraphNode node, 
            String entityType) {
        
        if (node.getLogs() == null || node.getLogs().isEmpty()) {
            return node.getNodeId();
        }
        
        RawLog log = node.getLogs().get(0);
        
        switch (entityType.toLowerCase()) {
            case "file":
                // file: fileMd5 + targetFilename
                String md5 = log.getFileMd5() != null ? log.getFileMd5() : "";
                String filename = log.getTargetFilename() != null ? log.getTargetFilename() : "";
                return "file_" + md5 + "_" + filename;
                
            case "domain":
                // domain: requestDomain
                String domain = log.getRequestDomain() != null ? log.getRequestDomain() : "";
                return "domain_" + domain;
                
            case "network":
                // network: destAddress
                String addr = log.getDestAddress() != null ? log.getDestAddress() : "";
                return "network_" + addr;
                
            case "registry":
                // registry: targetObject
                String obj = log.getTargetObject() != null ? log.getTargetObject() : "";
                return "registry_" + obj;
                
            default:
                return node.getNodeId();
        }
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
     * 规则：优先保留优先后缀，告警节点优先，保留前3个
     */
    private static List<GraphNode> filterFileNodes(
            List<GraphNode> nodes, int limit) {
        
        if (nodes.size() <= limit) {
            return nodes;
        }
        
        // 1. 分类：优先后缀 vs 普通文件
        List<GraphNode> priorityFiles = new ArrayList<>();
        List<GraphNode> normalFiles = new ArrayList<>();
        
        for (GraphNode node : nodes) {
            String filename = extractFilename(node);
            if (hasPriorityExtension(filename)) {
                priorityFiles.add(node);
            } else {
                normalFiles.add(node);
            }
        }
        
        // 2. 排序：告警节点优先，然后按时间
        Comparator<GraphNode> comparator = (a, b) -> {
            // 告警节点优先
            if (a.isAlarm() != b.isAlarm()) {
                return a.isAlarm() ? -1 : 1;
            }
            // 按时间排序（最新的）
            return compareByTime(a, b, false);
        };
        
        priorityFiles.sort(comparator);
        normalFiles.sort(comparator);
        
        // 3. 选择节点
        List<GraphNode> result = new ArrayList<>();
        
        // 先加入优先文件
        for (GraphNode node : priorityFiles) {
            if (result.size() >= limit) break;
            result.add(node);
        }
        
        // 如果还有空位，加入普通文件
        for (GraphNode node : normalFiles) {
            if (result.size() >= limit) break;
            result.add(node);
        }
        
        return result;
    }
    
    /**
     * 过滤domain节点
     * 规则：保留最新的5个
     */
    private static List<GraphNode> filterDomainNodes(
            List<GraphNode> nodes, int limit) {
        
        if (nodes.size() <= limit) {
            return nodes;
        }
        
        // 按时间降序排序（最新的在前）
        nodes.sort((a, b) -> compareByTime(a, b, false));
        
        return nodes.stream()
                .limit(limit)
                .collect(Collectors.toList());
    }
    
    /**
     * 过滤network节点
     * 规则：保留最新的5个
     */
    private static List<GraphNode> filterNetworkNodes(
            List<GraphNode> nodes, int limit) {
        
        if (nodes.size() <= limit) {
            return nodes;
        }
        
        // 与domain相同，保留最新的
        nodes.sort((a, b) -> compareByTime(a, b, false));
        
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
     */
    private static String extractFilename(GraphNode node) {
        if (node.getLogs() == null || node.getLogs().isEmpty()) {
            return "";
        }
        
        RawLog log = node.getLogs().get(0);
        String filename = log.getTargetFilename();
        
        if (filename == null || filename.isEmpty()) {
            filename = log.getFileName();
        }
        
        return filename != null ? filename : "";
    }
    
    /**
     * 提取开始时间
     */
    private static String extractStartTime(GraphNode node) {
        if (node.getLogs() == null || node.getLogs().isEmpty()) {
            return null;
        }
        
        RawLog log = node.getLogs().get(0);
        return log.getStartTime();
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

