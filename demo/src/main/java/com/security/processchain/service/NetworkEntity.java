package com.security.processchain.service;

/**
 * 网络实体
 */
public class NetworkEntity {
    private String transProtocol;
    private String srcAddress;
    private Integer srcPort;
    private String destAddress;
    private Integer destPort;
    private Boolean initiated;
    
    public NetworkEntity() {
        this.transProtocol = "";
        this.srcAddress = "";
        this.destAddress = "";
    }
    
    public String getTransProtocol() {
        return transProtocol;
    }
    
    public void setTransProtocol(String transProtocol) {
        this.transProtocol = transProtocol;
    }
    
    public String getSrcAddress() {
        return srcAddress;
    }
    
    public void setSrcAddress(String srcAddress) {
        this.srcAddress = srcAddress;
    }
    
    public Integer getSrcPort() {
        return srcPort;
    }
    
    public void setSrcPort(Integer srcPort) {
        this.srcPort = srcPort;
    }
    
    public String getDestAddress() {
        return destAddress;
    }
    
    public void setDestAddress(String destAddress) {
        this.destAddress = destAddress;
    }
    
    public Integer getDestPort() {
        return destPort;
    }
    
    public void setDestPort(Integer destPort) {
        this.destPort = destPort;
    }
    
    public Boolean getInitiated() {
        return initiated;
    }
    
    public void setInitiated(Boolean initiated) {
        this.initiated = initiated;
    }
}



