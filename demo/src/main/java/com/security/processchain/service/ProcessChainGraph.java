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
    
    /** 边的值：key="source->target", value=边的值（如"断链"） */
    private Map<String, String> edgeVals;
    
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
    
    /** 虚拟根父节点映射：子根节点ID -> 虚拟父节点ID
     * 用于 processGuid == parentProcessGuid == traceId 的场景 */
    private Map<String, String> virtualRootParentMap;
    
    public ProcessChainGraph() {
        this.nodes = new HashMap<>();
        this.outEdges = new HashMap<>();
        this.inEdges = new HashMap<>();
        this.edgeVals = new HashMap<>();
        this.nodesByTraceId = new HashMap<>();
        this.nodesByHost = new HashMap<>();
        this.rootNodes = new HashSet<>();
        this.brokenNodes = new HashSet<>();
        this.alarmNodes = new HashSet<>();
        this.traceIdToRootNodeMap = new HashMap<>();
        this.brokenNodeToTraceId = new HashMap<>();
        this.virtualRootParentMap = new HashMap<>();
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
        List<String> children = outEdges.get(source);
        return children != null && children.contains(target);
    }
    
    /**
     * 添加边
     */
    public void addEdge(String source, String target) {
        addEdge(source, target, "连接");
    }
    
    /**
     * 添加边（带值）
     * 
     * @param source 源节点
     * @param target 目标节点
     * @param val 边的值（如"断链"），null 表示普通边
     */
    public void addEdge(String source, String target, String val) {
        if (source == null || target == null) {
            return;
        }
        
        // 防止自环
        if (source.equals(target)) {
            log.debug("【建图】检测到自环，跳过: {}", source);
            return;
        }
        
        // 检查是否已存在（使用邻接表检测）
        List<String> children = outEdges.get(source);
        if (children != null && children.contains(target)) {
            log.debug("【建图】边已存在，跳过: {} → {}", source, target);
            return;  // 边已存在
        }
        
        // ✅ 检测潜在的反向边（环）
        List<String> reverseChildren = outEdges.get(target);
        if (reverseChildren != null && reverseChildren.contains(source)) {
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
        
        // 保存边的值（如果指定）
        if (val != null && !val.isEmpty()) {
            String edgeKey = source + "->" + target;
            edgeVals.put(edgeKey, val);
            log.debug("【建图】边的值已设置: {} → {}, val={}", source, target, val);
        }
    }
    
    /**
     * 获取边的值
     * 
     * @param source 源节点
     * @param target 目标节点
     * @return 边的值，如果没有设置则返回 null
     */
    public String getEdgeVal(String source, String target) {
        if (source == null || target == null) {
            return null;
        }
        String edgeKey = source + "->" + target;
        return edgeVals.get(edgeKey);
    }
    
    /**
     * 获取所有边的值
     * 
     * @return 边的值映射的副本
     */
    public Map<String, String> getEdgeVals() {
        return new HashMap<>(edgeVals);
    }
    
    /**
     * 添加虚拟根父节点映射
     * 用于 processGuid==parentProcessGuid==traceId 的场景
     * 
     * @param childRootNodeId 子根节点ID
     * @param virtualParentNodeId 虚拟父节点ID
     */
    public void addVirtualRootParentMapping(String childRootNodeId, String virtualParentNodeId) {
        if (childRootNodeId == null || virtualParentNodeId == null) {
            return;
        }
        virtualRootParentMap.put(childRootNodeId, virtualParentNodeId);
        log.debug("【映射添加】虚拟根父节点: {} -> {}", childRootNodeId, virtualParentNodeId);
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
    public void removeCutNode(String nodeId) {
        if (!nodes.containsKey(nodeId)) {
            return;
        }
        
        // 移除所有入边（父节点 -> 该节点）
        List<String> parents = getParents(nodeId);
        for (String parent : parents) {
            // 从父节点的子节点列表中移除
            List<String> parentChildren = outEdges.get(parent);
            if (parentChildren != null) {
                parentChildren.remove(nodeId);
            }
            
            // ✅ 移除边属性（parent -> nodeId）
            String edgeKey = parent + "->" + nodeId;
            edgeVals.remove(edgeKey);
        }
        
        // 移除所有出边（该节点 -> 子节点）
        List<String> children = getChildren(nodeId);
        for (String child : children) {
            // 从子节点的父节点列表中移除
            List<String> childParents = inEdges.get(child);
            if (childParents != null) {
                childParents.remove(nodeId);
            }
            
            // ✅ 移除边属性（nodeId -> child）
            String edgeKey = nodeId + "->" + child;
            edgeVals.remove(edgeKey);
        }
        
        // 移除节点及其相关数据结构
        nodes.remove(nodeId);
        outEdges.remove(nodeId);
        inEdges.remove(nodeId);
        rootNodes.remove(nodeId);
        brokenNodes.remove(nodeId);
        alarmNodes.remove(nodeId);
    }
    
    // ========== 图分析方法 ==========
    
    /**
     * 识别根节点、断链节点，并建立 traceId 到根节点的映射
     * 
     * <p><b>核心功能</b>：</p>
     * <ol>
     *   <li>识别所有根节点（包括真正的根节点和虚拟根父节点）</li>
     *   <li>识别所有断链节点（父节点缺失的节点）</li>
     *   <li>建立 traceId → rootNodeId 映射（用于网端桥接）</li>
     *   <li>处理虚拟根父节点的特殊映射覆盖逻辑</li>
     * </ol>
     * 
     * <p><b>识别规则</b>：</p>
     * <ul>
     *   <li><b>规则1：真正的根节点</b> - processGuid == traceId
     *       <pre>
     *       条件：nodeId.equals(node.getTraceId())
     *       操作：isRoot=true, 添加到 rootNodes, 建立映射 traceId → nodeId
     *       说明：这是实际意义上的进程链起点
     *       </pre>
     *   </li>
     *   <li><b>规则2：虚拟根父节点</b> - 入度为0 且 nodeId 以 "VIRTUAL_ROOT_PARENT_" 开头
     *       <pre>
     *       条件：getInDegree(nodeId) == 0 && nodeId.startsWith("VIRTUAL_ROOT_PARENT_")
     *       操作：
     *         1. isRoot=true, 添加到 rootNodes
     *         2. 覆盖原有映射：traceId → nodeId（虚拟父节点）
     *         3. 将原根节点的 isRoot 改为 false，从 rootNodes 移除
     *       说明：特殊根节点（processGuid==parentProcessGuid==traceId）的虚拟父节点
     *            用于支持网端桥接到正确的位置
     *       </pre>
     *   </li>
     *   <li><b>规则3：断链节点</b> - 入度为0 且 有 parentProcessGuid 但父节点不存在
     *       <pre>
     *       条件：getInDegree(nodeId) == 0 && parentProcessGuid != null && 父节点不是虚拟节点
     *       操作：isBroken=true, 添加到 brokenNodes, 记录 brokenNodeToTraceId 映射
     *       说明：父进程日志缺失，需要后续创建 EXPLORE 节点作为虚拟根
     *       </pre>
     *   </li>
     *   <li><b>规则4：其他根节点</b> - 入度为0 且 无 parentProcessGuid
     *       <pre>
     *       条件：getInDegree(nodeId) == 0 && parentProcessGuid == null
     *       操作：isRoot=true, 添加到 rootNodes, 建立映射 traceId → nodeId
     *       说明：自引用节点（processGuid==parentProcessGuid 且 已清空 parentProcessGuid）
     *       </pre>
     *   </li>
     * </ul>
     * 
     * <p><b>特殊处理</b>：</p>
     * <ul>
     *   <li><b>虚拟根父节点覆盖</b>：如果发现虚拟根父节点，会覆盖原根节点的映射
     *       <pre>
     *       初始：traceIdToRootNodeMap: {A -> A}  (原根节点)
     *       覆盖：traceIdToRootNodeMap: {A -> VIRTUAL_ROOT_PARENT_A}  (虚拟父节点)
     *       目的：确保网端桥接到虚拟父节点，而不是原根节点
     *       </pre>
     *   </li>
     *   <li><b>跳过虚拟父节点的子节点</b>：如果节点的 parentProcessGuid 指向虚拟节点
     *       （VIRTUAL_ROOT_PARENT_ 或 VIRTUAL_PARENT_ 开头），不标记为断链，
     *       等待后续虚拟节点创建后建立关系
     *   </li>
     * </ul>
     * 
     * <p><b>输出结果</b>：</p>
     * <ul>
     *   <li><b>rootNodes</b>：所有根节点的 ID 集合（用于遍历和展示）</li>
     *   <li><b>brokenNodes</b>：所有断链节点的 ID 集合（用于创建 EXPLORE 节点）</li>
     *   <li><b>traceIdToRootNodeMap</b>：traceId → 根节点ID 映射（用于网端桥接）
     *       <ul>
     *         <li>如果有虚拟根父节点，映射到虚拟父节点</li>
     *         <li>否则，映射到真正的根节点</li>
     *       </ul>
     *   </li>
     *   <li><b>brokenNodeToTraceId</b>：断链节点ID → traceId 映射（用于 EXPLORE 节点创建）</li>
     * </ul>
     * 
     * <p><b>使用场景</b>：</p>
     * <ol>
     *   <li>在 ProcessChainGraphBuilder.buildGraph() 构建完整图后调用</li>
     *   <li>在 ProcessChainBuilder.extractSubgraph() 提取子图后调用</li>
     *   <li>必须在网端桥接之前调用，确保 traceIdToRootNodeMap 正确</li>
     * </ol>
     * 
     * <p><b>示例</b>：</p>
     * <pre>
     * 场景1：普通根节点
     *   节点：A (processGuid=A, traceId=A, parentProcessGuid=null)
     *   结果：rootNodes=[A], traceIdToRootNodeMap={A->A}
     * 
     * 场景2：特殊根节点 + 虚拟根父节点
     *   节点：A (processGuid=A, traceId=A, parentProcessGuid=B)
     *   节点：B (VIRTUAL_ROOT_PARENT_A, traceId=A, parentProcessGuid=null)
     *   结果：
     *     rootNodes=[B]  (A 被移除)
     *     traceIdToRootNodeMap={A->B}  (覆盖原有的 A->A)
     *     A.isRoot=false, B.isRoot=true
     * 
     * 场景3：断链节点
     *   节点：X (processGuid=X, traceId=T1, parentProcessGuid=PARENT_UNKNOWN)
     *   父节点 PARENT_UNKNOWN 不存在
     *   结果：
     *     brokenNodes=[X]
     *     brokenNodeToTraceId={X->T1}
     *     traceIdToRootNodeMap={}  (空，需要后续创建 EXPLORE_ROOT_T1)
     * </pre>
     * 
     * @param traceIds 所有 traceId 集合（用于识别真正的根节点）
     */
    public void identifyRootNodes(Set<String> traceIds) {
        rootNodes.clear();
        brokenNodes.clear();
        traceIdToRootNodeMap.clear();
        brokenNodeToTraceId.clear();
        
        for (String nodeId : nodes.keySet()) {
            GraphNode node = nodes.get(nodeId);
            
            // ✅ 规则1：真正的根节点（processGuid == traceId）
            // 注意：nodeId 就是 processGuid
            if (nodeId.equals(node.getTraceId())) {
                rootNodes.add(nodeId);
                node.setRoot(true);
                traceIdToRootNodeMap.put(node.getTraceId(), nodeId);
                log.debug("【根节点识别】找到真正的根节点: {} (processGuid==traceId)", nodeId);
            } else if (getInDegree(nodeId) == 0) {            // 规则2：入度为0的节点（可能是虚拟根父节点或断链节点）
                // ✅ 特殊处理：虚拟根父节点（以 VIRTUAL_ROOT_PARENT_ 开头）
                if (nodeId.startsWith("VIRTUAL_ROOT_PARENT_")) {
                    rootNodes.add(nodeId);
                    node.setRoot(true);
                    
                    // 建立 traceId → rootNodeId 映射（覆盖原有映射，因为虚拟父节点才是真正的根）
                    String traceId = node.getTraceId();
                    if (traceId != null) {
                        String oldRootNodeId = traceIdToRootNodeMap.get(traceId);
                        traceIdToRootNodeMap.put(traceId, nodeId);
                        log.debug("【根节点识别】找到虚拟根父节点: {} (VIRTUAL_ROOT_PARENT), traceId={}, 替换原根节点: {}", 
                                nodeId, traceId, oldRootNodeId);
                        
                        // 将原来的子根节点的 isRoot 设置为 false
                        if (oldRootNodeId != null && nodes.containsKey(oldRootNodeId)) {
                            GraphNode oldRootNode = nodes.get(oldRootNodeId);
                            oldRootNode.setRoot(false);
                            rootNodes.remove(oldRootNodeId);
                            log.debug("【根节点识别】原根节点 {} 的 isRoot 改为 false", oldRootNodeId);
                        }
                    }
                } else {                // 不是虚拟根父节点，也不是真正的根节点（已被规则1处理）
                    if (node.getParentProcessGuid() != null && 
                        !node.getParentProcessGuid().isEmpty()) {
                        
                        // ✅ 新增：检查父节点是否是虚拟节点
                        // 如果 parentProcessGuid 以 VIRTUAL_ 开头，说明父节点是虚拟节点，可能还没创建，不应标记为断链
                        if (node.getParentProcessGuid().startsWith("VIRTUAL_ROOT_PARENT_") ||
                            node.getParentProcessGuid().startsWith("VIRTUAL_PARENT_")) {
                            log.debug("【根节点识别】跳过虚拟父节点的子节点: nodeId={}, virtualParentGuid={}, 等待虚拟节点创建后建立关系", 
                                    nodeId, node.getParentProcessGuid());
                            // 不标记为断链，也不标记为根节点，等待后续处理
                        } else {
                        // 有parentProcessGuid但找不到父节点 -> 断链
                        brokenNodes.add(nodeId);
                        node.setBroken(true);
                            
                            // 记录断链节点的traceId
                            String traceId = node.getTraceId();
                            if (traceId != null) {
                                brokenNodeToTraceId.put(nodeId, traceId);
                            }
                            
                            log.debug("【断链识别】找到断链节点: {} (入度0，有parentGuid={}), traceId={}", 
                                    nodeId, node.getParentProcessGuid(), traceId);
                        }
                    } else {
                        // ✅ 入度为0且没有parentGuid -> 也是根节点 自环的节点
                        rootNodes.add(nodeId);
                        node.setRoot(true);
                        
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
        }
        
        log.info("【图分析】根节点数={}, 断链节点数={}, traceId映射数={}", 
                rootNodes.size(), brokenNodes.size(), traceIdToRootNodeMap.size());
        
        // ⚠️ 如果有断链节点，映射可能为空（需要后续创建EXPLORE节点）
        if (!brokenNodes.isEmpty() && traceIdToRootNodeMap.isEmpty()) {
            log.warn("【图分析】⚠️ 检测到断链节点，但traceIdToRootNodeMap为空，将在后续创建EXPLORE（未知进程）节点");
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
        
        // 复制边（只保留两端都在nodeIds中的边），对应的点明确存在
        for (String nodeId : nodeIds) {
            List<String> children = getChildren(nodeId);
            for (String child : children) {
                if (nodeIds.contains(child)) {
                    subgraph.addEdge(nodeId, child);
                }
            }
        }
        
        // 复制根节点和断链节点标记
        subgraph.rootNodes.addAll(rootNodes);
        // 只在子图中的根节点
        subgraph.rootNodes.retainAll(nodeIds);
        
        subgraph.brokenNodes.addAll(brokenNodes);
        subgraph.brokenNodes.retainAll(nodeIds);
        
        // 复制映射关系
        subgraph.traceIdToRootNodeMap.putAll(traceIdToRootNodeMap);
        subgraph.brokenNodeToTraceId.putAll(brokenNodeToTraceId);
        subgraph.virtualRootParentMap.putAll(virtualRootParentMap);
        
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
    
    public int getEdgeCount() {
        int count = 0;
        for (List<String> edges : outEdges.values()) {
            count += edges.size();
        }
        return count;
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
    
    public Map<String, String> getVirtualRootParentMap() {
        return new HashMap<>(virtualRootParentMap);
    }
    
    /**
     * 获取所有出边（邻接表）
     * 
     * @return 出边映射的副本：nodeId -> [child1, child2, ...]
     */
    public Map<String, List<String>> getOutEdges() {
        Map<String, List<String>> copy = new HashMap<>();
        for (Map.Entry<String, List<String>> entry : outEdges.entrySet()) {
            copy.put(entry.getKey(), new ArrayList<>(entry.getValue()));
        }
        return copy;
    }
}

