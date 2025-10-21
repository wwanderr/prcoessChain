package com.security.processchain.service;

import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.ProcessEdge;
import java.util.List;

/**
 * 事件进程链
 */
public class IncidentProcessChain {
    private String traceId;
    private String hostAddress;
    private List<ProcessNode> nodes;
    private List<ProcessEdge> edges;
    private ThreatSeverity threatSeverity;
    
    public IncidentProcessChain() {}
    
    public String getTraceId() {
        return traceId;
    }
    
    public void setTraceId(String traceId) {
        this.traceId = traceId;
    }
    
    public String getHostAddress() {
        return hostAddress;
    }
    
    public void setHostAddress(String hostAddress) {
        this.hostAddress = hostAddress;
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



