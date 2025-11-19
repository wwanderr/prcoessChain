package com.security.processchain.service;

import com.security.processchain.service.ChainBuilderNode;
import java.util.*;

/**
 * 节点索引数据结构 - 多维度索引优化
 * 
 * 【核心功能】
 * 提供多维度的节点快速查找能力，避免遍历所有节点，提升性能
 * 
 * 【设计目标】
 * 1. 空间换时间：通过多个索引结构，将查询时间复杂度从 O(N) 降低到 O(1)
 * 2. 自动维护：添加/删除/更新节点时，自动维护所有索引的一致性
 * 3. 类型安全：通过不可变集合防止外部修改
 * 
 * 【使用场景】
 * - ProcessChainBuilder 构建进程链时，需要频繁查找和分类节点
 * - 替代原来的多个独立集合（rootNodes, brokenNodes 等），统一管理
 * 
 * 【性能优化】
 * - 原方案：遍历所有节点查找 → O(N)
 * - 新方案：索引直接查找 → O(1)
 * 
 * @author ProcessChain Team
 * @since 2.0
 */
public class NodeIndex {
    
    /**
     * 【主索引】processGuid -> ChainBuilderNode
     * 
     * 作用：根据进程 GUID 快速定位节点（最常用的查找方式）
     * 
     * 使用场景：
     * 1. traverseUpward() 中根据 processGuid 查找节点
     * 2. 构建边时，根据 source/target processGuid 查找节点
     * 3. 检查节点是否已存在
     * 
     * 时间复杂度：O(1)
     * 空间复杂度：O(N)，N 为节点总数
     * 
     * 示例：
     *   nodeIndex.getByGuid("PROC-12345") → 返回对应的 ChainBuilderNode
     */
    private final Map<String, ChainBuilderNode> nodesByGuid;
    
    /**
     * 【traceId 索引】traceId -> List<ChainBuilderNode>
     * 
     * 作用：根据 traceId 快速获取该溯源链的所有节点
     * 
     * 使用场景：
     * 1. 多 traceId 场景下，需要按 traceId 分组处理节点
     * 2. 统计某个 traceId 的节点数量
     * 3. 为某个 traceId 创建 EXPLORE_ROOT 节点时，需要知道该 traceId 有哪些节点
     * 
     * 时间复杂度：O(1) 查找，O(M) 遍历（M 为该 traceId 的节点数）
     * 空间复杂度：O(N)
     * 
     * 示例：
     *   nodeIndex.getByTraceId("TRACE-001") → 返回 [node1, node2, node3]
     * 
     * 注意：一个节点只属于一个 traceId
     */
    private final Map<String, List<ChainBuilderNode>> nodesByTraceId;
    
    /**
     * 【hostAddress 索引】hostAddress -> List<ChainBuilderNode>
     * 
     * 作用：根据主机 IP 地址快速获取该主机上的所有节点
     * 
     * 使用场景：
     * 1. 多 IP 场景下，需要按主机分组处理节点
     * 2. 统计某个主机的节点数量
     * 3. 网端桥接时，根据 victim IP 查找端侧节点
     * 
     * 时间复杂度：O(1) 查找，O(M) 遍历（M 为该主机的节点数）
     * 空间复杂度：O(N)
     * 
     * 示例：
     *   nodeIndex.getByHost("192.168.1.100") → 返回 [node1, node2, node3]
     * 
     * 注意：一个节点只属于一个主机
     */
    private final Map<String, List<ChainBuilderNode>> nodesByHost;
    
    /**
     * 【根节点索引】所有根节点的集合
     * 
     * 作用：快速获取所有根节点（进程链的起点）
     * 
     * 使用场景：
     * 1. 判断是否找到了真实根节点（foundRootNode）
     * 2. 创建 EXPLORE_ROOT 节点时，检查是否已有真实根节点
     * 3. 统计根节点数量
     * 4. 遍历所有根节点进行处理
     * 
     * 时间复杂度：O(1) 获取集合，O(K) 遍历（K 为根节点数）
     * 空间复杂度：O(K)
     * 
     * 示例：
     *   nodeIndex.getRootNodes() → 返回 {rootNode1, rootNode2}
     * 
     * 判断条件：node.getIsRoot() == true
     * 
     * 注意：
     * - 正常情况下，一个 traceId 只有一个真实根节点
     * - 如果没有真实根节点，会创建 EXPLORE_ROOT 虚拟根节点
     */
    private final Set<ChainBuilderNode> rootNodes;
    
    /**
     * 【断链节点索引】所有断链节点的集合
     * 
     * 作用：快速获取所有断链节点（找不到父节点的最顶端节点）
     * 
     * 使用场景：
     * 1. 判断是否存在断链（需要创建 EXPLORE_ROOT）
     * 2. 为断链节点创建到 EXPLORE_ROOT 的边
     * 3. 统计断链节点数量
     * 4. 遍历所有断链节点进行处理
     * 
     * 时间复杂度：O(1) 获取集合，O(K) 遍历（K 为断链节点数）
     * 空间复杂度：O(K)
     * 
     * 示例：
     *   nodeIndex.getBrokenNodes() → 返回 {brokenNode1, brokenNode2}
     * 
     * 判断条件：node.getIsBroken() == true
     * 
     * 断链定义：
     * - 当前节点不是根节点（processGuid 不在 traceIds 中）
     * - 且父节点的日志不存在于原始日志中
     * 
     * 处理方式：
     * - 为每个断链节点创建到对应 EXPLORE_ROOT_{traceId} 的边
     */
    private final Set<ChainBuilderNode> brokenNodes;
    
    /**
     * 【告警节点索引】所有告警节点的集合
     * 
     * 作用：快速获取所有包含告警的节点
     * 
     * 使用场景：
     * 1. 统计告警节点数量
     * 2. 遍历所有告警节点进行特殊处理（如优先级标记）
     * 3. 智能裁剪时，保护告警节点不被删除
     * 4. 网端关联时，标记关联的告警节点
     * 
     * 时间复杂度：O(1) 获取集合，O(K) 遍历（K 为告警节点数）
     * 空间复杂度：O(K)
     * 
     * 示例：
     *   nodeIndex.getAlarmNodes() → 返回 {alarmNode1, alarmNode2}
     * 
     * 判断条件：node.getIsAlarm() == true
     * 
     * 注意：
     * - 一个节点可能包含多个告警（同一个进程触发多次告警）
     * - 告警节点在进程链中具有最高优先级，不会被裁剪
     */
    private final Set<ChainBuilderNode> alarmNodes;
    
    public NodeIndex() {
        this.nodesByGuid = new HashMap<>();
        this.nodesByTraceId = new HashMap<>();
        this.nodesByHost = new HashMap<>();
        this.rootNodes = new HashSet<>();
        this.brokenNodes = new HashSet<>();
        this.alarmNodes = new HashSet<>();
    }
    
    /**
     * 添加节点到索引
     * 
     * 【功能】
     * 自动根据节点属性建立多维度索引，一次添加，多维索引
     * 
     * 【使用场景】
     * 1. ProcessChainBuilder.buildProcessChain() 中，将所有节点添加到索引
     * 2. 创建 EXPLORE_ROOT 虚拟节点后，将其添加到索引
     * 
     * 【自动索引维护】
     * - 如果节点有 processGuid → 添加到主索引
     * - 如果节点有 traceId → 添加到 traceId 索引
     * - 如果节点有 hostAddress → 添加到 hostAddress 索引
     * - 如果节点 isRoot=true → 添加到根节点索引
     * - 如果节点 isBroken=true → 添加到断链节点索引
     * - 如果节点 isAlarm=true → 添加到告警节点索引
     * 
     * 【注意事项】
     * - 如果 processGuid 已存在，会覆盖旧节点
     * - 节点属性为 null 时，不会添加到对应的索引
     * 
     * @param node 要添加的节点
     */
    public void addNode(ChainBuilderNode node) {
        if (node == null || node.getProcessGuid() == null) {
            return;
        }
        
        // 主索引
        nodesByGuid.put(node.getProcessGuid(), node);
        
        // traceId 索引
        if (node.getTraceId() != null) {
            nodesByTraceId.computeIfAbsent(node.getTraceId(), k -> new ArrayList<>()).add(node);
        }
        
        // hostAddress 索引
        if (node.getHostAddress() != null) {
            nodesByHost.computeIfAbsent(node.getHostAddress(), k -> new ArrayList<>()).add(node);
        }
        
        // 根节点索引
        if (Boolean.TRUE.equals(node.getIsRoot())) {
            rootNodes.add(node);
        }
        
        // 断链节点索引
        if (Boolean.TRUE.equals(node.getIsBroken())) {
            brokenNodes.add(node);
        }
        
        // 告警节点索引
        if (Boolean.TRUE.equals(node.getIsAlarm())) {
            alarmNodes.add(node);
        }
    }
    
    /**
     * 更新节点索引（当节点属性变化时）
     * 
     * 【功能】
     * 当节点的属性发生变化时（如 isRoot、isBroken 等），重新建立索引
     * 
     * 【使用场景】
     * 1. traverseUpward() 中，发现节点是根节点，设置 isRoot=true 后更新索引
     * 2. traverseUpward() 中，发现节点是断链节点，设置 isBroken=true 后更新索引
     * 3. 节点的 traceId 或 hostAddress 发生变化时
     * 
     * 【实现原理】
     * 先移除旧索引（基于旧属性），再添加新索引（基于新属性）
     * 
     * 【注意事项】
     * - 必须在修改节点属性后调用此方法，否则索引会不一致
     * - 性能开销：O(1) 删除 + O(1) 添加 = O(1)
     * 
     * @param node 要更新的节点
     */
    public void updateNode(ChainBuilderNode node) {
        if (node == null || node.getProcessGuid() == null) {
            return;
        }
        
        // 先移除旧索引
        removeNode(node.getProcessGuid());
        
        // 重新添加
        addNode(node);
    }
    
    /**
     * 移除节点
     * 
     * 【功能】
     * 从所有索引中移除指定的节点，保持索引一致性
     * 
     * 【使用场景】
     * 1. 智能裁剪时，删除低优先级节点
     * 2. 更新节点时，先移除旧索引
     * 3. 清理无效节点
     * 
     * 【自动清理】
     * - 从主索引中移除
     * - 从 traceId 索引中移除
     * - 从 hostAddress 索引中移除
     * - 从根节点索引中移除
     * - 从断链节点索引中移除
     * - 从告警节点索引中移除
     * 
     * 【注意事项】
     * - 如果索引列表为空，会自动清理该索引项（避免内存泄漏）
     * - 如果 processGuid 不存在，不会抛出异常，静默返回
     * 
     * @param processGuid 要移除的节点的 processGuid
     */
    public void removeNode(String processGuid) {
        ChainBuilderNode node = nodesByGuid.remove(processGuid);
        if (node == null) {
            return;
        }
        
        // 清理 traceId 索引
        if (node.getTraceId() != null) {
            List<ChainBuilderNode> nodes = nodesByTraceId.get(node.getTraceId());
            if (nodes != null) {
                nodes.remove(node);
                if (nodes.isEmpty()) {
                    nodesByTraceId.remove(node.getTraceId());
                }
            }
        }
        
        // 清理 hostAddress 索引
        if (node.getHostAddress() != null) {
            List<ChainBuilderNode> nodes = nodesByHost.get(node.getHostAddress());
            if (nodes != null) {
                nodes.remove(node);
                if (nodes.isEmpty()) {
                    nodesByHost.remove(node.getHostAddress());
                }
            }
        }
        
        // 清理其他索引
        rootNodes.remove(node);
        brokenNodes.remove(node);
        alarmNodes.remove(node);
    }
    
    // ========== 查询方法 ==========
    
    /**
     * 按 processGuid 查找节点
     * 
     * 【使用场景】
     * 1. traverseUpward() 中根据 processGuid 查找当前节点
     * 2. 构建边时，根据 source/target processGuid 查找节点
     * 3. 检查节点是否已存在
     * 
     * 【时间复杂度】O(1)
     * 
     * @param processGuid 进程 GUID
     * @return 对应的节点，如果不存在返回 null
     */
    public ChainBuilderNode getByGuid(String processGuid) {
        return nodesByGuid.get(processGuid);
    }
    
    /**
     * 按 traceId 查找所有节点
     * 
     * 【使用场景】
     * 1. 多 traceId 场景下，按 traceId 分组处理节点
     * 2. 统计某个 traceId 的节点数量
     * 3. 为某个 traceId 创建 EXPLORE_ROOT 节点
     * 
     * 【时间复杂度】O(1) 查找，O(M) 遍历（M 为该 traceId 的节点数）
     * 
     * @param traceId 溯源 ID
     * @return 该 traceId 的所有节点列表，如果不存在返回空列表
     */
    public List<ChainBuilderNode> getByTraceId(String traceId) {
        return nodesByTraceId.getOrDefault(traceId, Collections.emptyList());
    }
    
    /**
     * 按 hostAddress 查找所有节点
     * 
     * 【使用场景】
     * 1. 多 IP 场景下，按主机分组处理节点
     * 2. 统计某个主机的节点数量
     * 3. 网端桥接时，根据 victim IP 查找端侧节点
     * 
     * 【时间复杂度】O(1) 查找，O(M) 遍历（M 为该主机的节点数）
     * 
     * @param hostAddress 主机 IP 地址
     * @return 该主机的所有节点列表，如果不存在返回空列表
     */
    public List<ChainBuilderNode> getByHost(String hostAddress) {
        return nodesByHost.getOrDefault(hostAddress, Collections.emptyList());
    }
    
    /**
     * 获取所有根节点
     * 
     * 【使用场景】
     * 1. 判断是否找到了真实根节点（foundRootNode）
     * 2. 创建 EXPLORE_ROOT 节点时，检查是否已有真实根节点
     * 3. 统计根节点数量
     * 
     * 【时间复杂度】O(1) 获取集合，O(K) 遍历（K 为根节点数）
     * 
     * @return 所有根节点的不可变集合
     */
    public Set<ChainBuilderNode> getRootNodes() {
        return Collections.unmodifiableSet(rootNodes);
    }
    
    /**
     * 获取所有断链节点
     * 
     * 【使用场景】
     * 1. 判断是否存在断链（需要创建 EXPLORE_ROOT）
     * 2. 为断链节点创建到 EXPLORE_ROOT 的边
     * 3. 统计断链节点数量
     * 
     * 【时间复杂度】O(1) 获取集合，O(K) 遍历（K 为断链节点数）
     * 
     * @return 所有断链节点的不可变集合
     */
    public Set<ChainBuilderNode> getBrokenNodes() {
        return Collections.unmodifiableSet(brokenNodes);
    }
    
    /**
     * 获取所有告警节点
     * 
     * 【使用场景】
     * 1. 统计告警节点数量
     * 2. 遍历所有告警节点进行特殊处理
     * 3. 智能裁剪时，保护告警节点不被删除
     * 
     * 【时间复杂度】O(1) 获取集合，O(K) 遍历（K 为告警节点数）
     * 
     * @return 所有告警节点的不可变集合
     */
    public Set<ChainBuilderNode> getAlarmNodes() {
        return Collections.unmodifiableSet(alarmNodes);
    }
    
    /**
     * 获取所有节点
     * 
     * 【使用场景】
     * 1. 遍历所有节点进行统计
     * 2. 转换节点为输出格式
     * 3. 智能裁剪时，遍历所有节点计算优先级
     * 
     * 【时间复杂度】O(1) 获取集合，O(N) 遍历（N 为节点总数）
     * 
     * @return 所有节点的不可变集合
     */
    public Collection<ChainBuilderNode> getAllNodes() {
        return Collections.unmodifiableCollection(nodesByGuid.values());
    }
    
    /**
     * 获取节点总数
     * 
     * 【使用场景】
     * 1. 判断是否超过节点数量上限
     * 2. 统计信息输出
     * 3. 智能裁剪前检查节点数量
     * 
     * 【时间复杂度】O(1)
     * 
     * @return 节点总数
     */
    public int size() {
        return nodesByGuid.size();
    }
    
    /**
     * 判断是否包含某个节点
     * 
     * 【使用场景】
     * 1. 避免重复添加节点
     * 2. 检查节点是否存在
     * 
     * 【时间复杂度】O(1)
     * 
     * @param processGuid 进程 GUID
     * @return 如果包含返回 true，否则返回 false
     */
    public boolean containsNode(String processGuid) {
        return nodesByGuid.containsKey(processGuid);
    }
    
    /**
     * 清空所有索引
     * 
     * 【使用场景】
     * 1. 重置索引状态
     * 2. 释放内存
     * 
     * 【注意事项】
     * 清空后，所有查询都将返回空结果
     */
    public void clear() {
        nodesByGuid.clear();
        nodesByTraceId.clear();
        nodesByHost.clear();
        rootNodes.clear();
        brokenNodes.clear();
        alarmNodes.clear();
    }
    
    /**
     * 获取所有 traceId
     * 
     * 【使用场景】
     * 1. 遍历所有 traceId 进行分组处理
     * 2. 统计 traceId 数量
     * 3. 为每个 traceId 创建 EXPLORE_ROOT 节点
     * 
     * 【时间复杂度】O(1) 获取集合，O(K) 遍历（K 为 traceId 数量）
     * 
     * @return 所有 traceId 的不可变集合
     */
    public Set<String> getAllTraceIds() {
        return Collections.unmodifiableSet(nodesByTraceId.keySet());
    }
    
    /**
     * 获取所有 hostAddress
     * 
     * 【使用场景】
     * 1. 遍历所有主机进行分组处理
     * 2. 统计主机数量
     * 3. 多 IP 场景下的统计信息
     * 
     * 【时间复杂度】O(1) 获取集合，O(K) 遍历（K 为主机数量）
     * 
     * @return 所有 hostAddress 的不可变集合
     */
    public Set<String> getAllHosts() {
        return Collections.unmodifiableSet(nodesByHost.keySet());
    }
}

