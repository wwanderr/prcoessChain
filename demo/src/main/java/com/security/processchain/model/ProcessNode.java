package com.security.processchain.model;

import com.security.processchain.service.ChainNode;
import com.security.processchain.service.NodeType;
import com.security.processchain.service.StoryNode;
import com.security.processchain.service.ThreatSeverity;

/**
 * 进程节点（最终返回给前端的完整节点结构）
 * 包含进程链节点和故事线节点的完整信息
 */
public class ProcessNode {
    /**
     * 原始数据类型："file", "network", "domain", "process"
     */
    private NodeType logType;
    
    /**
     * 节点风险等级
     */
    private ThreatSeverity nodeThreatSeverity;
    
    /**
     * 节点ID（进程链中为parentProcessGuid，故事线中为victim等）
     */
    private String nodeId;
    
    /**
     * 节点类型标识（true表示进程链节点，false表示故事线节点）
     */
    private Boolean isChainNode;
    
    /**
     * 进程链节点详情（当isChainNode为true时使用）
     */
    private ChainNode chainNode;
    
    /**
     * 故事线节点详情（当isChainNode为false时使用）
     */
    private StoryNode storyNode;
    
    /**
     * 子节点数量（该节点下挂的直接子节点个数）
     */
    private Integer childrenCount;
    
    // Getters and Setters
    
    public NodeType getLogType() {
        return logType;
    }
    
    public void setLogType(NodeType logType) {
        this.logType = logType;
    }
    
    public ThreatSeverity getNodeThreatSeverity() {
        return nodeThreatSeverity;
    }
    
    public void setNodeThreatSeverity(ThreatSeverity nodeThreatSeverity) {
        this.nodeThreatSeverity = nodeThreatSeverity;
    }
    
    public String getNodeId() {
        return nodeId;
    }
    
    public void setNodeId(String nodeId) {
        this.nodeId = nodeId;
    }
    
    public Boolean getIsChainNode() {
        return isChainNode;
    }
    
    public void setIsChainNode(Boolean isChainNode) {
        this.isChainNode = isChainNode;
    }
    
    public ChainNode getChainNode() {
        return chainNode;
    }
    
    public void setChainNode(ChainNode chainNode) {
        this.chainNode = chainNode;
    }
    
    public StoryNode getStoryNode() {
        return storyNode;
    }
    
    public void setStoryNode(StoryNode storyNode) {
        this.storyNode = storyNode;
    }
    
    public Integer getChildrenCount() {
        return childrenCount;
    }
    
    public void setChildrenCount(Integer childrenCount) {
        this.childrenCount = childrenCount;
    }
}


