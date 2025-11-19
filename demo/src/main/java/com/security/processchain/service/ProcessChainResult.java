package com.security.processchain.service;

import lombok.Getter;
import lombok.Setter;

import java.util.*;

/**
 * 进程链构建结果
 * 优化版本：使用 NodeIndex 替代多个独立集合，简化数据结构
 */
@Getter
@Setter
public class ProcessChainResult {
    // 节点索引（包含所有节点及其多维度索引）
    private NodeIndex nodeIndex = new NodeIndex();
    
    // 边列表
    private List<ChainBuilderEdge> edges = new ArrayList<>();
    
    // traceId 到根节点ID的映射
    private Map<String, String> traceIdToRootNodeMap = new HashMap<>();
    
    // 断链节点到 traceId 的映射
    private Map<String, String> brokenNodeToTraceId = new HashMap<>();
    
    // ========== 便捷方法 ==========
    
    /**
     * 获取所有节点列表
     */
    public List<ChainBuilderNode> getNodes() {
        return new ArrayList<>(nodeIndex.getAllNodes());
    }
    
    /**
     * 设置节点列表（会重建索引）
     */
    public void setNodes(List<ChainBuilderNode> nodes) {
        nodeIndex.clear();
        if (nodes != null) {
            for (ChainBuilderNode node : nodes) {
                nodeIndex.addNode(node);
            }
        }
    }
    
    /**
     * 是否找到了根节点
     */
    public boolean isFoundRootNode() {
        return !nodeIndex.getRootNodes().isEmpty();
    }
    
    /**
     * 获取根节点ID集合
     */
    public Set<String> getRootNodes() {
        Set<String> rootNodeIds = new HashSet<>();
        for (ChainBuilderNode node : nodeIndex.getRootNodes()) {
            rootNodeIds.add(node.getProcessGuid());
        }
        return rootNodeIds;
    }
    
    /**
     * 设置根节点（已废弃，由 NodeIndex 自动管理）
     * @deprecated 使用 NodeIndex 自动管理根节点
     */
    @Deprecated
    public void setRootNodes(Set<String> rootNodes) {
        // 兼容旧代码，不做任何操作
    }
    
    /**
     * 获取断链节点ID集合
     */
    public Set<String> getBrokenNodes() {
        Set<String> brokenNodeIds = new HashSet<>();
        for (ChainBuilderNode node : nodeIndex.getBrokenNodes()) {
            brokenNodeIds.add(node.getProcessGuid());
        }
        return brokenNodeIds;
    }
    
    /**
     * 设置断链节点（已废弃，由 NodeIndex 自动管理）
     * @deprecated 使用 NodeIndex 自动管理断链节点
     */
    @Deprecated
    public void setBrokenNodes(Set<String> brokenNodes) {
        // 兼容旧代码，不做任何操作
    }
    
    /**
     * 设置 foundRootNode（已废弃，由 NodeIndex 自动计算）
     * @deprecated 使用 isFoundRootNode() 自动计算
     */
    @Deprecated
    public void setFoundRootNode(boolean foundRootNode) {
        // 兼容旧代码，不做任何操作
    }
}

