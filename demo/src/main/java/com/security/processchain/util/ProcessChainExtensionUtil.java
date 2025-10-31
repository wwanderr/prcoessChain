package com.security.processchain.util;

import com.security.processchain.model.ProcessEdge;
import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.IncidentConverters;
import com.security.processchain.service.OptimizedESQueryService;
import com.security.processchain.service.ProcessChainBuilder;
import com.security.processchain.service.ProcessEntity;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * 进程链扩展工具类
 * 负责从根节点向上扩展溯源（最多2层）
 * 
 * <h3>核心功能</h3>
 * <ol>
 *   <li>从 isRoot 节点向上查询父节点（最多2层）</li>
 *   <li>构建扩展节点和边</li>
 *   <li>更新 isRoot 标记到最顶端节点</li>
 *   <li>自动跳过断链节点和 Explore 虚拟节点</li>
 * </ol>
 * 
 * <h3>使用场景</h3>
 * <p>当进程链构建完成后，有时需要看到根节点（isRoot=true）的父进程，以了解更完整的攻击上下文。
 * 此工具类提供了非破坏性的扩展机制，在不影响原有构建逻辑的前提下，向上扩展最多2层父节点。</p>
 * 
 * <h3>工作原理示意图</h3>
 * <pre>
 * 原始进程链：
 *   isRoot(T001) → 子进程1 → 子进程2
 *   
 * 扩展后：
 *   祖父进程(新Root) → 父进程 → isRoot(T001) → 子进程1 → 子进程2
 *        ↑                ↑
 *   扩展层2          扩展层1
 *   isExtensionNode=true  isExtensionNode=true
 *   extensionDepth=2      extensionDepth=1
 * </pre>
 * 
 * <h3>桥接点调整</h3>
 * <p>如果存在网侧进程链需要桥接到端侧，扩展后会自动调整桥接点：</p>
 * <pre>
 * 扩展前: 网侧victim → 桥接边 → isRoot(T001) → 子进程...
 * 扩展后: 网侧victim → 桥接边 → 祖父进程 → 父进程 → isRoot(T001) → 子进程...
 * </pre>
 * 
 * <h3>智能跳过策略</h3>
 * <ul>
 *   <li><b>Explore节点</b>: 节点ID以"EXPLORE_"开头的虚拟节点会被跳过</li>
 *   <li><b>断链节点</b>: isBroken=true的节点会被跳过（因为无法继续向上溯源）</li>
 * </ul>
 * 
 * @author AI Assistant
 * @since 2025-10-27
 */
@Slf4j
public class ProcessChainExtensionUtil {
    
    /**
     * 执行扩展溯源（主入口方法）
     * 
     * <p><b>功能说明</b>：遍历所有 traceId 对应的根节点，尝试向上扩展最多 maxDepth 层父节点。</p>
     * 
     * <p><b>处理流程</b>：</p>
     * <ol>
     *   <li>遍历 traceIdToRootMap 中的每个根节点</li>
     *   <li>检查是否需要跳过（Explore节点或断链节点）</li>
     *   <li>如果不需要跳过，调用 extendFromNode() 执行扩展</li>
     *   <li>如果扩展成功（找到父节点），更新 isRoot 标记</li>
     *   <li>返回更新后的映射（traceId -> 最顶端节点ID）</li>
     * </ol>
     * 
     * <p><b>示例</b>：</p>
     * <pre>
     * 输入：traceIdToRootMap = {"T001" -> "NODE_ROOT_001"}
     * 输出：{"T001" -> "NODE_GRANDPARENT_001"} （如果扩展成功）
     *      或 {"T001" -> "NODE_ROOT_001"} （如果无法扩展）
     * </pre>
     * 
     * @param traceIdToRootMap 原始的 traceId -> 根节点ID 映射（来自 ProcessChainBuilder）
     * @param hostToTraceId host -> traceId 映射（用于反向查找 hostAddress）
     * @param allNodes 所有节点列表（会在此列表中添加扩展节点，原地修改）
     * @param allEdges 所有边列表（会在此列表中添加扩展边，原地修改）
     * @param esQueryService ES查询服务（用于查询父节点的日志）
     * @param maxDepth 最大扩展深度（推荐值：2，表示最多向上扩展2层）
     * @return 更新后的 traceId -> 根节点ID 映射（桥接时应使用此映射）
     */
    public static Map<String, String> performExtension(
            Map<String, String> traceIdToRootMap,
            Map<String, String> hostToTraceId,
            List<ProcessNode> allNodes,
            List<ProcessEdge> allEdges,
            OptimizedESQueryService esQueryService,
            int maxDepth) {
        
        log.info("【扩展溯源】-> 开始扩展，最大深度: {}", maxDepth);
        
        // 存储更新后的映射关系
        Map<String, String> updatedMap = new HashMap<>();
        int extensionCount = 0; // 统计成功扩展的数量
        
        // 遍历每个 traceId 对应的根节点
        for (Map.Entry<String, String> entry : traceIdToRootMap.entrySet()) {
            String traceId = entry.getKey();
            String originalRootId = entry.getValue(); // 原始根节点ID
            
            // ========== 步骤1：检查是否需要跳过 ==========
            // 跳过条件：1) Explore虚拟节点  2) 断链节点
            if (shouldSkipExtension(originalRootId, allNodes)) {
                updatedMap.put(traceId, originalRootId); // 保持原样
                continue;
            }
            
            // ========== 步骤2：执行扩展 ==========
            // 从原始根节点向上查询父节点，返回最顶端节点ID
            String newTopNodeId = extendFromNode(
                    originalRootId, traceId, hostToTraceId, 
                    allNodes, allEdges, esQueryService, maxDepth);
            
            // ========== 步骤3：处理扩展结果 ==========
            if (!newTopNodeId.equals(originalRootId)) {
                // 扩展成功！找到了更上层的父节点
                updatedMap.put(traceId, newTopNodeId); // 更新映射到最顶端节点
                updateRootFlag(originalRootId, newTopNodeId, allNodes); // 调整isRoot标记
                extensionCount++;
                
                log.info("【扩展溯源】-> traceId={} 扩展成功: {} -> {}", 
                        traceId, originalRootId, newTopNodeId);
            } else {
                // 扩展失败（无父节点或查询失败），保持原映射
                updatedMap.put(traceId, originalRootId);
            }
        }
        
        log.info("【扩展溯源】-> 扩展完成，成功扩展 {} 个链", extensionCount);
        return updatedMap;
    }
    
    /**
     * 检查是否应该跳过扩展
     * 
     * <p><b>跳过条件</b>：</p>
     * <ol>
     *   <li><b>Explore 虚拟节点</b>：节点ID以"EXPLORE_"开头的节点是系统创建的虚拟节点，
     *       用于连接断链，这类节点没有实际的父进程，无需扩展</li>
     *   <li><b>断链节点</b>：isBroken=true 的节点表示其父节点日志缺失，
     *       无法继续向上追溯，因此跳过扩展</li>
     * </ol>
     * 
     * @param nodeId 节点ID
     * @param allNodes 所有节点列表
     * @return true-需要跳过，false-可以扩展
     */
    private static boolean shouldSkipExtension(String nodeId, List<ProcessNode> allNodes) {
        // ========== 跳过条件1：Explore 虚拟节点 ==========
        if (nodeId != null && nodeId.startsWith("EXPLORE_")) {
            log.debug("【扩展溯源】-> 跳过 Explore 虚拟节点: {}", nodeId);
            return true;
        }
        
        // ========== 跳过条件2：断链节点 ==========
        ProcessNode node = findNodeById(allNodes, nodeId);
        if (node != null && node.getIsChainNode() && node.getChainNode() != null) {
            if (Boolean.TRUE.equals(node.getChainNode().getIsBroken())) {
                log.debug("【扩展溯源】-> 跳过断链节点: {}", nodeId);
                return true;
            }
        }
        
        return false; // 不需要跳过，可以扩展
    }
    
    /**
     * 从指定节点向上扩展
     * 
     * <p><b>功能说明</b>：从指定的根节点向上查询父节点，并递归构建扩展链。</p>
     * 
     * <p><b>处理流程</b>：</p>
     * <ol>
     *   <li>获取原始根节点的 parentProcessGuid</li>
     *   <li>通过 traceId 反向查找对应的 hostAddress</li>
     *   <li>调用 ES 查询服务，查询父节点及其祖先节点的日志（最多 maxDepth 层）</li>
     *   <li>将查询到的日志按 processGuid 分组</li>
     *   <li>调用 buildExtensionChain() 递归构建扩展链</li>
     * </ol>
     * 
     * <p><b>返回值说明</b>：</p>
     * <ul>
     *   <li>如果扩展成功：返回最顶端节点的ID（例如：祖父节点ID）</li>
     *   <li>如果扩展失败：返回原始根节点ID（保持不变）</li>
     * </ul>
     * 
     * @param originalRootId 原始根节点ID
     * @param traceId 溯源ID
     * @param hostToTraceId host -> traceId 映射
     * @param allNodes 所有节点列表（会添加扩展节点）
     * @param allEdges 所有边列表（会添加扩展边）
     * @param esQueryService ES查询服务
     * @param maxDepth 最大扩展深度
     * @return 最顶端节点ID（扩展成功）或原始根节点ID（扩展失败）
     */
    private static String extendFromNode(
            String originalRootId,
            String traceId,
            Map<String, String> hostToTraceId,
            List<ProcessNode> allNodes,
            List<ProcessEdge> allEdges,
            OptimizedESQueryService esQueryService,
            int maxDepth) {
        
        // ========== 步骤1：查找原始根节点 ==========
        ProcessNode originalNode = findNodeById(allNodes, originalRootId);
        if (originalNode == null || !originalNode.getIsChainNode()) {
            return originalRootId; // 节点不存在或不是进程链节点，无法扩展
        }
        
        // ========== 步骤2：获取父节点 GUID ==========
        ProcessEntity processEntity = originalNode.getChainNode().getProcessEntity();
        if (processEntity == null || processEntity.getParentProcessGuid() == null) {
            log.debug("【扩展溯源】-> 节点 {} 无父节点", originalRootId);
            return originalRootId; // 无父节点信息，无法扩展
        }
        
        String parentGuid = processEntity.getParentProcessGuid();
        
        // ========== 步骤3：获取 hostAddress ==========
        // 需要知道主机地址才能查询 ES
        String hostAddress = getHostAddressForTraceId(traceId, hostToTraceId);
        if (hostAddress == null) {
            log.warn("【扩展溯源】-> 无法获取 traceId={} 的 hostAddress", traceId);
            return originalRootId;
        }
        
        // ========== 步骤4：查询父节点日志 ==========
        try {
            List<String> parentGuids = Arrays.asList(parentGuid);
            
            // 调用 ES 查询服务，查询父节点及其祖先的日志
            // 注意：queryLogsByProcessGuids 方法会递归查询 maxDepth 层
            List<RawLog> extensionLogs = esQueryService.queryLogsByProcessGuids(
                    hostAddress, parentGuids, maxDepth);
            
            if (extensionLogs.isEmpty()) {
                log.debug("【扩展溯源】-> 未查询到父节点日志: {}", parentGuid);
                return originalRootId; // 查询为空，无法扩展
            }
            
            // ========== 步骤5：按 processGuid 分组 ==========
            // 将日志按进程GUID分组，方便后续构建节点
            Map<String, List<RawLog>> logsByGuid = groupLogsByProcessGuid(extensionLogs);
            
            // ========== 步骤6：递归构建扩展链 ==========
            // 从父节点开始，递归向上构建扩展链，返回最顶端节点ID
            return buildExtensionChain(
                    originalRootId,    // 子节点ID（原始根节点）
                    parentGuid,        // 当前节点ID（父节点）
                    logsByGuid,        // 日志数据
                    allNodes,          // 节点列表（会添加新节点）
                    allEdges,          // 边列表（会添加新边）
                    1,                 // 当前深度（从1开始）
                    maxDepth);         // 最大深度
            
        } catch (Exception e) {
            log.error("【扩展溯源】-> 查询失败: {}", e.getMessage(), e);
            return originalRootId; // 异常情况，保持原样
        }
    }
    
    /**
     * 递归构建扩展链，返回最顶端节点ID
     * 
     * <p><b>功能说明</b>：这是一个递归方法，从指定节点开始向上构建扩展链，直到达到最大深度或无父节点。</p>
     * 
     * <p><b>递归逻辑</b>：</p>
     * <pre>
     * buildExtensionChain(原始根节点, 父节点, ..., depth=1)
     *   ├─ 创建父节点（depth=1，extensionDepth=1）
     *   ├─ 添加边：父节点 -> 原始根节点
     *   └─ 递归调用：buildExtensionChain(父节点, 祖父节点, ..., depth=2)
     *        ├─ 创建祖父节点（depth=2，extensionDepth=2）
     *        ├─ 添加边：祖父节点 -> 父节点
     *        └─ 返回祖父节点ID（无更高层或达到maxDepth）
     * </pre>
     * 
     * <p><b>终止条件</b>：</p>
     * <ol>
     *   <li>当前节点没有对应的日志数据</li>
     *   <li>当前节点的 parentProcessGuid 为 null</li>
     *   <li>达到最大深度 (depth >= maxDepth)</li>
     *   <li>父节点的日志不在 logsByGuid 中</li>
     * </ol>
     * 
     * @param childGuid 子节点ID（下层节点，最初是原始根节点）
     * @param currentGuid 当前节点ID（正在处理的节点）
     * @param logsByGuid 日志数据（按processGuid分组）
     * @param allNodes 所有节点列表（会添加新节点）
     * @param allEdges 所有边列表（会添加新边）
     * @param depth 当前深度（1=父节点，2=祖父节点）
     * @param maxDepth 最大深度限制
     * @return 最顶端节点的ID
     */
    private static String buildExtensionChain(
            String childGuid,
            String currentGuid,
            Map<String, List<RawLog>> logsByGuid,
            List<ProcessNode> allNodes,
            List<ProcessEdge> allEdges,
            int depth,
            int maxDepth) {
        
        // ========== 终止条件1：当前节点无日志数据 ==========
        if (!logsByGuid.containsKey(currentGuid)) {
            return childGuid; // 返回子节点作为顶端节点
        }
        
        // ========== 步骤1：创建扩展节点 ==========
        if (findNodeById(allNodes, currentGuid) == null) {
            // 节点不存在，需要创建
            List<RawLog> logs = logsByGuid.get(currentGuid);
            ProcessNode newNode = convertLogsToNode(currentGuid, logs);
            
            // 标记为扩展节点，并设置扩展深度
            if (newNode.getChainNode() != null) {
                newNode.getChainNode().setIsExtensionNode(true);
                newNode.getChainNode().setExtensionDepth(depth);
            }
            
            allNodes.add(newNode);
            log.debug("【扩展溯源】-> 添加扩展节点: guid={}, depth={}", currentGuid, depth);
        }
        
        // ========== 步骤2：添加边（父子关系）==========
        // 创建边：当前节点(父) -> 子节点
        ProcessEdge edge = new ProcessEdge();
        edge.setSource(currentGuid);  // 父节点
        edge.setTarget(childGuid);     // 子节点
        edge.setVal("");              // 边的值（暂时为空）
        allEdges.add(edge);
        
        // ========== 步骤3：检查是否继续向上递归 ==========
        List<RawLog> logs = logsByGuid.get(currentGuid);
        String parentGuid = logs.get(0).getParentProcessGuid(); // 获取父进程GUID
        
        // 终止条件检查
        if (parentGuid == null || depth >= maxDepth || !logsByGuid.containsKey(parentGuid)) {
            // 无父节点 或 达到最大深度 或 父节点日志不存在
            return currentGuid; // 当前节点就是最顶端节点
        }
        
        // ========== 步骤4：递归向上构建 ==========
        // 继续向上一层，depth+1
        return buildExtensionChain(
                currentGuid,           // 当前节点变成子节点
                parentGuid,            // 父节点变成当前节点
                logsByGuid, 
                allNodes, 
                allEdges, 
                depth + 1,             // 深度+1
                maxDepth);
    }
    
    /**
     * 更新 isRoot 标记
     * 
     * <p><b>功能说明</b>：扩展成功后，需要调整 isRoot 标记：</p>
     * <ul>
     *   <li>将原始根节点的 isRoot 改为 false（它不再是最顶端）</li>
     *   <li>将新的最顶端节点的 isRoot 改为 true（它成为新的根节点）</li>
     * </ul>
     * 
     * <p><b>示例</b>：</p>
     * <pre>
     * 扩展前：
     *   - NODE_001: isRoot=true  (原始根节点)
     * 
     * 扩展后（找到祖父节点 NODE_GRAND）：
     *   - NODE_001: isRoot=false (不再是根)
     *   - NODE_GRAND: isRoot=true (新的根节点)
     * </pre>
     * 
     * @param oldRootId 原始根节点ID
     * @param newRootId 新的最顶端节点ID
     * @param allNodes 所有节点列表
     */
    private static void updateRootFlag(String oldRootId, String newRootId, List<ProcessNode> allNodes) {
        for (ProcessNode node : allNodes) {
            // 只处理进程链节点
            if (!node.getIsChainNode() || node.getChainNode() == null) {
                continue;
            }
            
            String nodeId = node.getNodeId();
            
            if (nodeId.equals(oldRootId)) {
                // ========== 原根节点：isRoot 改为 false ==========
                node.getChainNode().setIsRoot(false);
                log.debug("【扩展溯源】-> 节点 {} 的 isRoot 改为 false", oldRootId);
            } else if (nodeId.equals(newRootId)) {
                // ========== 新根节点：isRoot 改为 true ==========
                node.getChainNode().setIsRoot(true);
                log.debug("【扩展溯源】-> 节点 {} 的 isRoot 改为 true", newRootId);
            }
        }
    }
    
    // ========== 辅助方法 ==========
    
    /**
     * 根据节点ID查找节点
     * 
     * @param nodes 节点列表
     * @param nodeId 节点ID
     * @return 找到的节点，或 null
     */
    private static ProcessNode findNodeById(List<ProcessNode> nodes, String nodeId) {
        if (nodes == null || nodeId == null) {
            return null;
        }
        return nodes.stream()
                .filter(n -> nodeId.equals(n.getNodeId()))
                .findFirst()
                .orElse(null);
    }
    
    /**
     * 根据 traceId 反向查找对应的 hostAddress
     * 
     * <p>因为映射关系是 host -> traceId，需要反向查找</p>
     * 
     * @param traceId 溯源ID
     * @param hostToTraceId host -> traceId 映射
     * @return hostAddress，或 null
     */
    private static String getHostAddressForTraceId(String traceId, Map<String, String> hostToTraceId) {
        if (hostToTraceId == null || traceId == null) {
            return null;
        }
        return hostToTraceId.entrySet().stream()
                .filter(e -> traceId.equals(e.getValue()))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse(null);
    }
    
    /**
     * 将日志列表按 processGuid 分组
     * 
     * <p>将查询到的日志按进程GUID分组，方便后续为每个进程创建节点</p>
     * 
     * @param logs 日志列表
     * @return processGuid -> 日志列表 的映射
     */
    private static Map<String, List<RawLog>> groupLogsByProcessGuid(List<RawLog> logs) {
        Map<String, List<RawLog>> grouped = new HashMap<>();
        if (logs == null) {
            return grouped;
        }
        for (RawLog log : logs) {
            if (log != null && log.getProcessGuid() != null) {
                // 使用 computeIfAbsent 自动创建列表并添加日志
                grouped.computeIfAbsent(log.getProcessGuid(), k -> new ArrayList<>()).add(log);
            }
        }
        return grouped;
    }
    
    /**
     * 将日志列表转换为 ProcessNode
     * 
     * <p><b>转换流程</b>：</p>
     * <ol>
     *   <li>创建 ChainBuilderNode（构建器内部节点）</li>
     *   <li>将所有日志添加到 ChainBuilderNode</li>
     *   <li>提取 parentProcessGuid</li>
     *   <li>使用 IncidentConverters.NODE_MAPPER 转换为 ProcessNode</li>
     * </ol>
     * 
     * @param guid 进程GUID
     * @param logs 日志列表
     * @return 转换后的 ProcessNode
     */
    private static ProcessNode convertLogsToNode(String guid, List<RawLog> logs) {
        // ========== 步骤1：创建构建器节点 ==========
        ProcessChainBuilder.ChainBuilderNode builderNode = new ProcessChainBuilder.ChainBuilderNode();
        builderNode.setProcessGuid(guid);
        
        // ========== 步骤2：添加日志数据 ==========
        if (logs != null) {
            logs.forEach(builderNode::addLog); // 将每条日志添加到节点
            
            // ========== 步骤3：提取父进程GUID ==========
            if (!logs.isEmpty() && logs.get(0) != null) {
                builderNode.setParentProcessGuid(logs.get(0).getParentProcessGuid());
            }
        }
        
        // ========== 步骤4：转换为 ProcessNode ==========
        // 使用转换器将 ChainBuilderNode 转换为最终的 ProcessNode
        return IncidentConverters.NODE_MAPPER.toIncidentNode(builderNode);
    }
    
    /**
     * 计算每个节点的子节点数量
     * 
     * <p><b>功能说明</b>：统计每个节点在进程链中的直接子节点数量。</p>
     * 
     * <p><b>实现原理</b>：</p>
     * <ol>
     *   <li>遍历所有边，统计每个节点作为 source（父节点）出现的次数</li>
     *   <li>将统计结果设置到对应的 ProcessNode.childrenCount 字段</li>
     * </ol>
     * 
     * <p><b>适用场景</b>：</p>
     * <ul>
     *   <li>端侧进程链构建完成后</li>
     *   <li>网端合并完成后（推荐位置，包含所有节点和边）</li>
     *   <li>扩展溯源完成后</li>
     * </ul>
     * 
     * <p><b>性能</b>：</p>
     * <ul>
     *   <li>时间复杂度：O(E + N)，其中 E 是边数，N 是节点数</li>
     *   <li>空间复杂度：O(N)，用于存储节点ID到子节点数的映射</li>
     * </ul>
     * 
     * @param nodes 节点列表（会原地修改每个节点的 childrenCount 字段）
     * @param edges 边列表
     */
    public static void calculateChildrenCount(
            List<ProcessNode> nodes,
            List<ProcessEdge> edges) {
        
        if (nodes == null || edges == null) {
            log.debug("【子节点统计】-> 跳过计算：节点或边列表为空");
            return;
        }
        
        // 步骤1: 统计每个节点作为 source 的次数（即子节点数量）
        // key: nodeId (source), value: 子节点数量
        Map<String, Integer> childrenCountMap = new HashMap<>();
        for (ProcessEdge edge : edges) {
            String source = edge.getSource();
            if (source != null) {
                childrenCountMap.put(source, childrenCountMap.getOrDefault(source, 0) + 1);
            }
        }
        
        // 步骤2: 为每个节点设置子节点数量
        for (ProcessNode node : nodes) {
            String nodeId = node.getNodeId();
            int count = childrenCountMap.getOrDefault(nodeId, 0);
            node.setChildrenCount(count);
        }
        
        log.debug("【子节点统计】-> 完成子节点数量计算，共处理 {} 个节点，{} 条边", 
                nodes.size(), edges.size());
    }
}

