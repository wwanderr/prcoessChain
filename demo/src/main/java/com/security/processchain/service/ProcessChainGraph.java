package com.security.processchain.service;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * 进程链图（有向图）
 * 
 * 采用邻接表表示，支持高效的图操作和遍历
 * 
 * 核心功能：
 * 1. 节点和边的管理
 * 2. 根节点识别
 * 3. 环检测
 * 4. BFS/DFS遍历
 * 5. 子图提取
 */
@Slf4j
public class ProcessChainGraph {
    
    // ========== 核心数据结构 ==========
    
    /** 节点存储：nodeId -> GraphNode */
    private Map<String, GraphNode> nodes;
    
    /** 出边（邻接表）：nodeId -> [child1, child2, ...] */
    private Map<String, List<String>> outEdges;
    
    /** 入边（反向邻接表）：nodeId -> [parent1, parent2, ...] */
    private Map<String, List<String>> inEdges;
    
    /** 边的属性：edgeKey(source->target) -> EdgeInfo */
    private Map<String, EdgeInfo> edgeProperties;
    
    // ========== 索引结构 ==========
    
    /** traceId索引：traceId -> [nodeId1, nodeId2, ...] */
    private Map<String, List<String>> nodesByTraceId;
    
    /** host索引：hostAddress -> [nodeId1, nodeId2, ...] */
    private Map<String, List<String>> nodesByHost;
    
    /** 根节点集合 */
    private Set<String> rootNodes;
    
    /** 断链节点集合 */
    private Set<String> brokenNodes;
    
    /** 告警节点集合 */
    private Set<String> alarmNodes;
    
    /** traceId到根节点ID的映射 */
    private Map<String, String> traceIdToRootNodeMap;
    
    /** 断链节点到traceId的映射 */
    private Map<String, String> brokenNodeToTraceId;
    
    public ProcessChainGraph() {
        this.nodes = new HashMap<>();
        this.outEdges = new HashMap<>();
        this.inEdges = new HashMap<>();
        this.edgeProperties = new HashMap<>();
        this.nodesByTraceId = new HashMap<>();
        this.nodesByHost = new HashMap<>();
        this.rootNodes = new HashSet<>();
        this.brokenNodes = new HashSet<>();
        this.alarmNodes = new HashSet<>();
        this.traceIdToRootNodeMap = new HashMap<>();
        this.brokenNodeToTraceId = new HashMap<>();
    }
    
    // ========== 基础操作 ==========
    
    /**
     * 添加节点
     */
    public void addNode(GraphNode node) {
        if (node == null || node.getNodeId() == null) {
            return;
        }
        
        String nodeId = node.getNodeId();
        nodes.put(nodeId, node);
        
        // 更新索引
        if (node.getTraceId() != null) {
            nodesByTraceId.computeIfAbsent(node.getTraceId(), k -> new ArrayList<>())
                          .add(nodeId);
        }
        
        if (node.getHostAddress() != null) {
            nodesByHost.computeIfAbsent(node.getHostAddress(), k -> new ArrayList<>())
                       .add(nodeId);
        }
        
        // 更新告警节点集合
        if (node.isAlarm()) {
            alarmNodes.add(nodeId);
        }
    }
    
    /**
     * 检查边是否存在
     */
    public boolean hasEdge(String source, String target) {
        if (source == null || target == null) {
            return false;
        }
        String edgeKey = source + "->" + target;
        return edgeProperties.containsKey(edgeKey);
    }
    
    /**
     * 添加边
     */
    public void addEdge(String source, String target) {
        addEdge(source, target, null);
    }
    
    /**
     * 添加边（带属性）
     */
    public void addEdge(String source, String target, EdgeInfo edgeInfo) {
        if (source == null || target == null) {
            return;
        }
        
        // 防止自环
        if (source.equals(target)) {
            log.debug("【建图】检测到自环，跳过: {}", source);
            return;
        }
        
        // 检查是否已存在
        String edgeKey = source + "->" + target;
        if (edgeProperties.containsKey(edgeKey)) {
            log.debug("【建图】边已存在，跳过: {} → {}", source, target);
            return;  // 边已存在
        }
        
        // ✅ 检测潜在的反向边（环）
        String reverseEdgeKey = target + "->" + source;
        if (edgeProperties.containsKey(reverseEdgeKey)) {
            log.warn("【建图】⚠️ 检测到反向边！将创建环路:");
            log.warn("  - 已存在边: {} → {}", target, source);
            log.warn("  - 尝试创建: {} → {}", source, target);
            log.warn("  - 这将形成环: {} ⇄ {}", source, target);
            
            // 打印堆栈，帮助定位是谁创建的这条边
            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
            log.warn("  - 调用栈:");
            for (int i = 2; i < Math.min(8, stack.length); i++) {
                log.warn("    {}", stack[i]);
            }
        }
        
        // 添加到出边表
        outEdges.computeIfAbsent(source, k -> new ArrayList<>())
                .add(target);
        
        // 添加到入边表
        inEdges.computeIfAbsent(target, k -> new ArrayList<>())
               .add(source);
        
        // 存储边的属性
        if (edgeInfo != null) {
            edgeProperties.put(edgeKey, edgeInfo);
        } else {
            edgeProperties.put(edgeKey, new EdgeInfo("连接", "default"));
        }
    }
    
    /**
     * 获取节点
     */
    public GraphNode getNode(String nodeId) {
        return nodes.get(nodeId);
    }
    
    /**
     * 检查节点是否存在
     */
    public boolean hasNode(String nodeId) {
        return nodes.containsKey(nodeId);
    }
    
    /**
     * 获取节点的所有子节点
     */
    public List<String> getChildren(String nodeId) {
        return outEdges.getOrDefault(nodeId, Collections.emptyList());
    }
    
    /**
     * 获取节点的所有父节点
     */
    public List<String> getParents(String nodeId) {
        return inEdges.getOrDefault(nodeId, Collections.emptyList());
    }
    
    /**
     * 获取节点的入度
     */
    public int getInDegree(String nodeId) {
        List<String> parents = inEdges.get(nodeId);
        return parents != null ? parents.size() : 0;
    }
    
    /**
     * 获取节点的出度
     */
    public int getOutDegree(String nodeId) {
        List<String> children = outEdges.get(nodeId);
        return children != null ? children.size() : 0;
    }
    
    /**
     * 移除节点（同时移除相关边）
     */
    public void removeNode(String nodeId) {
        if (!nodes.containsKey(nodeId)) {
            return;
        }
        
        // 移除所有入边
        List<String> parents = getParents(nodeId);
        for (String parent : parents) {
            List<String> parentChildren = outEdges.get(parent);
            if (parentChildren != null) {
                parentChildren.remove(nodeId);
            }
            edgeProperties.remove(parent + "->" + nodeId);
        }
        
        // 移除所有出边
        List<String> children = getChildren(nodeId);
        for (String child : children) {
            List<String> childParents = inEdges.get(child);
            if (childParents != null) {
                childParents.remove(nodeId);
            }
            edgeProperties.remove(nodeId + "->" + child);
        }
        
        // 移除节点
        nodes.remove(nodeId);
        outEdges.remove(nodeId);
        inEdges.remove(nodeId);
        rootNodes.remove(nodeId);
        brokenNodes.remove(nodeId);
        alarmNodes.remove(nodeId);
    }
    
    // ========== 图分析方法 ==========
    
    /**
     * 识别根节点
     * 
     * 规则：
     * 1. processGuid 在 traceIds 中（真实根节点）
     * 2. 入度为0且有parentProcessGuid（断链）
     */
    public void identifyRootNodes(Set<String> traceIds) {
        rootNodes.clear();
        brokenNodes.clear();
        traceIdToRootNodeMap.clear();
        brokenNodeToTraceId.clear();
        
        for (String nodeId : nodes.keySet()) {
            GraphNode node = nodes.get(nodeId);
            
            // 规则1：processGuid == traceId
            if (traceIds.contains(nodeId)) {
                rootNodes.add(nodeId);
                node.setIsRoot(true);
                traceIdToRootNodeMap.put(nodeId, nodeId);
                log.debug("【根节点识别】找到根节点: {} (processGuid匹配traceId)", nodeId);
            }
            // 规则2：入度为0
            else if (getInDegree(nodeId) == 0) {
                if (node.getParentProcessGuid() != null && 
                    !node.getParentProcessGuid().isEmpty()) {
                    // 有parentProcessGuid但找不到父节点 -> 断链
                    brokenNodes.add(nodeId);
                    node.setIsBroken(true);
                    
                    // 记录断链节点的traceId
                    String traceId = node.getTraceId();
                    if (traceId != null) {
                        brokenNodeToTraceId.put(nodeId, traceId);
                    }
                    
                    log.debug("【断链识别】找到断链节点: {} (入度0，有parentGuid), traceId={}", 
                            nodeId, traceId);
                } else {
                    // ✅ 入度为0且没有parentGuid -> 也是根节点（虚拟父节点）
                    rootNodes.add(nodeId);
                    node.setIsRoot(true);
                    
                    // 建立 traceId → rootNodeId 映射
                    String traceId = node.getTraceId();
                    if (traceId != null && !traceIdToRootNodeMap.containsKey(traceId)) {
                        traceIdToRootNodeMap.put(traceId, nodeId);
                        log.debug("【根节点识别】找到根节点: {} (入度0，无parentGuid), traceId={}", 
                                nodeId, traceId);
                    }
                }
            }
        }
        
        log.info("【图分析】根节点数={}, 断链节点数={}, traceId映射数={}", 
                rootNodes.size(), brokenNodes.size(), traceIdToRootNodeMap.size());
        
        // ⚠️ 如果有断链节点，映射可能为空（需要后续创建EXPLORE节点）
        if (!brokenNodes.isEmpty() && traceIdToRootNodeMap.isEmpty()) {
            log.warn("【图分析】⚠️ 检测到断链节点，但traceIdToRootNodeMap为空，将在后续创建EXPLORE节点");
            log.warn("【图分析】断链节点列表: {}", brokenNodes);
            log.warn("【图分析】brokenNodeToTraceId: {}", brokenNodeToTraceId);
        } else {
            log.info("【图分析】traceIdToRootNodeMap: {}", traceIdToRootNodeMap);
        }
    }
    
    /**
     * 检测环（使用DFS着色法）
     * 
     * @return 所有环中的节点集合
     */
    public Set<String> detectCycles() {
        Set<String> cycleNodes = new HashSet<>();
        Map<String, NodeColor> colors = new HashMap<>();
        
        // 初始化：所有节点为白色（未访问）
        for (String nodeId : nodes.keySet()) {
            colors.put(nodeId, NodeColor.WHITE);
        }
        
        // 对每个白色节点进行DFS
        for (String nodeId : nodes.keySet()) {
            if (colors.get(nodeId) == NodeColor.WHITE) {
                detectCyclesDFS(nodeId, colors, cycleNodes);
            }
        }
        
        if (!cycleNodes.isEmpty()) {
            log.warn("【环检测】检测到 {} 个环中的节点", cycleNodes.size());
        }
        
        return cycleNodes;
    }
    
    /**
     * DFS检测环
     */
    private boolean detectCyclesDFS(String nodeId, 
                                    Map<String, NodeColor> colors,
                                    Set<String> cycleNodes) {
        // 标记为灰色（正在访问）
        colors.put(nodeId, NodeColor.GRAY);
        
        // 访问所有子节点
        List<String> children = getChildren(nodeId);
        for (String child : children) {
            NodeColor childColor = colors.get(child);
            
            if (childColor == NodeColor.GRAY) {
                // 发现环：子节点是灰色，说明还在当前DFS路径中
                cycleNodes.add(child);
                cycleNodes.add(nodeId);
                log.warn("【环检测】发现环: {} -> {}", nodeId, child);
                return true;
            }
            
            if (childColor == NodeColor.WHITE) {
                if (detectCyclesDFS(child, colors, cycleNodes)) {
                    cycleNodes.add(nodeId);
                    return true;
                }
            }
        }
        
        // 标记为黑色（已完成）
        colors.put(nodeId, NodeColor.BLACK);
        return false;
    }
    
    /**
     * BFS遍历（单向）
     * 
     * @param startNodeId 起点节点
     * @param direction true=向上（父节点），false=向下（子节点）
     * @return 遍历到的所有节点ID
     */
    public Set<String> bfsTraversal(String startNodeId, boolean direction) {
        Set<String> visited = new HashSet<>();
        Queue<String> queue = new LinkedList<>();
        
        queue.offer(startNodeId);
        visited.add(startNodeId);
        
        while (!queue.isEmpty()) {
            String current = queue.poll();
            
            // 获取相邻节点
            List<String> neighbors = direction ? getParents(current) : getChildren(current);
            
            for (String neighbor : neighbors) {
                if (!visited.contains(neighbor)) {
                    visited.add(neighbor);
                    queue.offer(neighbor);
                }
            }
        }
        
        return visited;
    }
    
    /**
     * 多分支全树遍历（针对需求3）
     * 
     * 算法：
     * 1. 从起点向上BFS到root，记录路径
     * 2. 对路径上的每个节点，向下BFS遍历所有子树
     */
    public Set<String> fullTreeTraversal(String startNodeId) {
        Set<String> result = new HashSet<>();
        
        // 阶段1：向上遍历到root，收集路径
        List<String> upwardPath = new ArrayList<>();
        Set<String> upwardVisited = new HashSet<>();
        
        Queue<String> upQueue = new LinkedList<>();
        upQueue.offer(startNodeId);
        upwardVisited.add(startNodeId);
        upwardPath.add(startNodeId);
        
        while (!upQueue.isEmpty()) {
            String current = upQueue.poll();
            GraphNode node = nodes.get(current);
            
            // 如果到达root，停止
            if (node != null && node.isRoot()) {
                log.debug("【全树遍历】到达根节点: {}", current);
                break;
            }
            
            // 继续向上
            List<String> parents = getParents(current);
            for (String parent : parents) {
                if (!upwardVisited.contains(parent)) {
                    upwardVisited.add(parent);
                    upwardPath.add(parent);
                    upQueue.offer(parent);
                }
            }
        }
        
        log.info("【全树遍历】向上路径长度: {}", upwardPath.size());
        
        // 阶段2：对路径上的每个节点，向下遍历所有子树
        for (String nodeInPath : upwardPath) {
            Set<String> downwardNodes = bfsTraversal(nodeInPath, false);
            result.addAll(downwardNodes);
        }
        
        // 统计各类型节点数量
        int processCount = 0;
        int entityCount = 0;
        for (String nodeId : result) {
            GraphNode node = nodes.get(nodeId);
            if (node != null) {
                String nodeType = node.getNodeType();
                if (nodeType != null && nodeType.endsWith("_entity")) {
                    entityCount++;
                } else {
                    processCount++;
                }
            }
        }
        
        log.info("【全树遍历】总节点数: {}, 进程节点: {}, 实体节点: {}", 
                result.size(), processCount, entityCount);
        
        return result;
    }
    
    /**
     * 提取子图
     * 
     * @param nodeIds 要包含的节点ID集合
     * @return 新的子图
     */
    public ProcessChainGraph extractSubgraph(Set<String> nodeIds) {
        ProcessChainGraph subgraph = new ProcessChainGraph();
        
        // 复制节点
        for (String nodeId : nodeIds) {
            GraphNode node = nodes.get(nodeId);
            if (node != null) {
                subgraph.addNode(node);
            }
        }
        
        // 复制边（只保留两端都在nodeIds中的边）
        for (String nodeId : nodeIds) {
            List<String> children = getChildren(nodeId);
            for (String child : children) {
                if (nodeIds.contains(child)) {
                    String edgeKey = nodeId + "->" + child;
                    EdgeInfo edgeInfo = edgeProperties.get(edgeKey);
                    subgraph.addEdge(nodeId, child, edgeInfo);
                }
            }
        }
        
        // 复制根节点和断链节点标记
        subgraph.rootNodes.addAll(rootNodes);
        subgraph.rootNodes.retainAll(nodeIds);
        
        subgraph.brokenNodes.addAll(brokenNodes);
        subgraph.brokenNodes.retainAll(nodeIds);
        
        // 复制映射关系
        subgraph.traceIdToRootNodeMap.putAll(traceIdToRootNodeMap);
        subgraph.brokenNodeToTraceId.putAll(brokenNodeToTraceId);
        
        return subgraph;
    }
    
    // ========== Getters ==========
    
    public Collection<GraphNode> getAllNodes() {
        return nodes.values();
    }
    
    public Set<String> getNodeIds() {
        return nodes.keySet();
    }
    
    public int getNodeCount() {
        return nodes.size();
    }
    
    public Set<String> getRootNodes() {
        return new HashSet<>(rootNodes);
    }
    
    public Set<String> getBrokenNodes() {
        return new HashSet<>(brokenNodes);
    }
    
    public Set<String> getAlarmNodes() {
        return new HashSet<>(alarmNodes);
    }
    
    public Map<String, String> getTraceIdToRootNodeMap() {
        return new HashMap<>(traceIdToRootNodeMap);
    }
    
    public Map<String, String> getBrokenNodeToTraceId() {
        return new HashMap<>(brokenNodeToTraceId);
    }
    
    public EdgeInfo getEdgeInfo(String edgeKey) {
        return edgeProperties.get(edgeKey);
    }
    
    /**
     * 获取所有边（格式：source->target）
     */
    public List<String> getAllEdgeKeys() {
        return new ArrayList<>(edgeProperties.keySet());
    }
}

