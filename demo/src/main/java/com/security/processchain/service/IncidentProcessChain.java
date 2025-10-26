package com.security.processchain.service;

import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.ProcessEdge;
import java.util.List;
import java.util.Map;

/**
 * 事件进程链
 * 支持多个 IP 和多个 traceId
 */
public class IncidentProcessChain {
    private List<String> traceIds;        // 改为 List，支持多个 traceId
    private List<String> hostAddresses;   // 改为 List，支持多个 IP
    private List<ProcessNode> nodes;
    private List<ProcessEdge> edges;
    private ThreatSeverity threatSeverity;
    
    public IncidentProcessChain() {}
    
    public List<String> getTraceIds() {
        return traceIds;
    }
    
    public void setTraceIds(List<String> traceIds) {
        this.traceIds = traceIds;
    }
    
    public List<String> getHostAddresses() {
        return hostAddresses;
    }
    
    public void setHostAddresses(List<String> hostAddresses) {
        this.hostAddresses = hostAddresses;
    }
    
    public List<ProcessNode> getNodes() {
        return nodes;
    }
    
    public void setNodes(List<ProcessNode> nodes) {
        this.nodes = nodes;
    }
    
    public List<ProcessEdge> getEdges() {
        return edges;
    }
    
    public void setEdges(List<ProcessEdge> edges) {
        this.edges = edges;
    }
    
    public ThreatSeverity getThreatSeverity() {
        return threatSeverity;
    }
    
    public void setThreatSeverity(ThreatSeverity threatSeverity) {
        this.threatSeverity = threatSeverity;
    }
}



