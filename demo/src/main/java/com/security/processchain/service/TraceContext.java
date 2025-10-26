package com.security.processchain.service;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.ProcessChainBuilder.ChainBuilderNode;
import com.security.processchain.service.ProcessChainBuilder.ChainBuilderEdge;
import java.util.*;

/**
 * 溯源上下文对象
 * 封装进程链构建过程中的所有上下文信息，简化方法签名
 * 
 * 优化点：
 * 1. 减少方法参数数量，提高代码可读性
 * 2. 集中管理上下文数据，便于扩展
 * 3. 提供便捷的查询方法，避免重复代码
 */
public class TraceContext {
    
    // ========== 输入数据 ==========
    
    // 告警列表
    private final List<RawAlarm> alarms;
    
    // 日志列表
    private final List<RawLog> logs;
    
    // 溯源ID集合
    private final Set<String> traceIds;
    
    // 网端关联的 eventId 集合
    private final Set<String> associatedEventIds;
    
    // ========== 索引数据 ==========
    
    // 按 processGuid 索引的日志
    private final Map<String, List<RawLog>> logsByProcessGuid;
    
    // 按 parentProcessGuid 索引的日志
    private final Map<String, List<RawLog>> logsByParentProcessGuid;
    
    // 节点索引
    private final NodeIndex nodeIndex;
    
    // ========== 映射关系 ==========
    
    // traceId -> 根节点ID 映射
    private final Map<String, String> traceIdToRootNodeMap;
    
    // hostAddress -> traceId 映射
    private final Map<String, String> hostToTraceIdMap;
    
    // ========== 构建结果 ==========
    
    // 边列表
    private final List<ChainBuilderEdge> edges;
    
    public TraceContext(List<RawAlarm> alarms, List<RawLog> logs, 
                       Set<String> traceIds, Set<String> associatedEventIds) {
        this.alarms = alarms != null ? alarms : Collections.emptyList();
        this.logs = logs != null ? logs : Collections.emptyList();
        this.traceIds = traceIds != null ? new HashSet<>(traceIds) : new HashSet<>();
        this.associatedEventIds = associatedEventIds != null ? new HashSet<>(associatedEventIds) : new HashSet<>();
        
        this.logsByProcessGuid = new HashMap<>();
        this.logsByParentProcessGuid = new HashMap<>();
        this.nodeIndex = new NodeIndex();
        this.traceIdToRootNodeMap = new HashMap<>();
        this.hostToTraceIdMap = new HashMap<>();
        this.edges = new ArrayList<>();
    }
    
    // ========== Getter 方法 ==========
    
    public List<RawAlarm> getAlarms() {
        return alarms;
    }
    
    public List<RawLog> getLogs() {
        return logs;
    }
    
    public Set<String> getTraceIds() {
        return traceIds;
    }
    
    public Set<String> getAssociatedEventIds() {
        return associatedEventIds;
    }
    
    public Map<String, List<RawLog>> getLogsByProcessGuid() {
        return logsByProcessGuid;
    }
    
    public Map<String, List<RawLog>> getLogsByParentProcessGuid() {
        return logsByParentProcessGuid;
    }
    
    public NodeIndex getNodeIndex() {
        return nodeIndex;
    }
    
    public Map<String, String> getTraceIdToRootNodeMap() {
        return traceIdToRootNodeMap;
    }
    
    public Map<String, String> getHostToTraceIdMap() {
        return hostToTraceIdMap;
    }
    
    public List<ChainBuilderEdge> getEdges() {
        return edges;
    }
    
    // ========== 便捷查询方法 ==========
    
    /**
     * 判断是否为网端关联的告警
     */
    public boolean isAssociatedAlarm(RawAlarm alarm) {
        return alarm != null && 
               alarm.getEventId() != null && 
               associatedEventIds.contains(alarm.getEventId());
    }
    
    /**
     * 判断 processGuid 是否匹配任一 traceId
     */
    public boolean matchesAnyTraceId(String processGuid) {
        if (processGuid == null || traceIds.isEmpty()) {
            return false;
        }
        for (String traceId : traceIds) {
            if (traceId.equals(processGuid)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 获取某个节点的日志
     */
    public List<RawLog> getLogsForNode(String processGuid) {
        return logsByProcessGuid.getOrDefault(processGuid, Collections.emptyList());
    }
    
    /**
     * 获取某个父节点的子节点日志
     */
    public List<RawLog> getLogsForParent(String parentProcessGuid) {
        return logsByParentProcessGuid.getOrDefault(parentProcessGuid, Collections.emptyList());
    }
    
    /**
     * 添加节点到索引
     */
    public void addNode(ChainBuilderNode node) {
        nodeIndex.addNode(node);
    }
    
    /**
     * 获取节点
     */
    public ChainBuilderNode getNode(String processGuid) {
        return nodeIndex.getByGuid(processGuid);
    }
    
    /**
     * 添加边
     */
    public void addEdge(ChainBuilderEdge edge) {
        if (edge != null) {
            edges.add(edge);
        }
    }
    
    /**
     * 记录 traceId 到根节点的映射
     */
    public void mapTraceIdToRoot(String traceId, String rootNodeId) {
        if (traceId != null && rootNodeId != null) {
            traceIdToRootNodeMap.put(traceId, rootNodeId);
        }
    }
    
    /**
     * 记录 host 到 traceId 的映射
     */
    public void mapHostToTraceId(String hostAddress, String traceId) {
        if (hostAddress != null && traceId != null) {
            hostToTraceIdMap.put(hostAddress, traceId);
        }
    }
    
    /**
     * 获取某个 traceId 的根节点ID
     */
    public String getRootNodeIdForTraceId(String traceId) {
        return traceIdToRootNodeMap.get(traceId);
    }
    
    /**
     * 获取某个 host 的 traceId
     */
    public String getTraceIdForHost(String hostAddress) {
        return hostToTraceIdMap.get(hostAddress);
    }
    
    /**
     * 获取所有根节点
     */
    public Set<ChainBuilderNode> getRootNodes() {
        return nodeIndex.getRootNodes();
    }
    
    /**
     * 获取所有断链节点
     */
    public Set<ChainBuilderNode> getBrokenNodes() {
        return nodeIndex.getBrokenNodes();
    }
    
    /**
     * 获取所有告警节点
     */
    public Set<ChainBuilderNode> getAlarmNodes() {
        return nodeIndex.getAlarmNodes();
    }
    
    /**
     * 获取节点总数
     */
    public int getNodeCount() {
        return nodeIndex.size();
    }
    
    /**
     * 获取边总数
     */
    public int getEdgeCount() {
        return edges.size();
    }
}

