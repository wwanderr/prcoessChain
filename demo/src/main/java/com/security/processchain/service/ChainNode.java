package com.security.processchain.service;

/**
 * 进程链节点详情
 */
public class ChainNode {
    private Boolean isRoot;
    private Boolean isBroken;
    private Boolean isAlarm;
    private AlarmNodeInfo alarmNodeInfo;
    private ProcessEntity processEntity;
    private Object entity;
    
    /**
     * 是否是扩展节点（从逻辑根向上扩展出来的节点）
     * 用于前端区分显示样式
     */
    private Boolean isExtensionNode;
    
    /**
     * 扩展深度（从逻辑根开始，0=逻辑根本身，1=父节点，2=祖父节点）
     */
    private Integer extensionDepth;
    
    public ChainNode() {}
    
    public Boolean getIsRoot() {
        return isRoot;
    }
    
    public void setIsRoot(Boolean isRoot) {
        this.isRoot = isRoot;
    }
    
    public Boolean getIsBroken() {
        return isBroken;
    }
    
    public void setIsBroken(Boolean isBroken) {
        this.isBroken = isBroken;
    }
    
    public Boolean getIsAlarm() {
        return isAlarm;
    }
    
    public void setIsAlarm(Boolean isAlarm) {
        this.isAlarm = isAlarm;
    }
    
    public AlarmNodeInfo getAlarmNodeInfo() {
        return alarmNodeInfo;
    }
    
    public void setAlarmNodeInfo(AlarmNodeInfo alarmNodeInfo) {
        this.alarmNodeInfo = alarmNodeInfo;
    }
    
    public ProcessEntity getProcessEntity() {
        return processEntity;
    }
    
    public void setProcessEntity(ProcessEntity processEntity) {
        this.processEntity = processEntity;
    }
    
    public Object getEntity() {
        return entity;
    }
    
    public void setEntity(Object entity) {
        this.entity = entity;
    }
    
    public Boolean getIsExtensionNode() {
        return isExtensionNode;
    }
    
    public void setIsExtensionNode(Boolean isExtensionNode) {
        this.isExtensionNode = isExtensionNode;
    }
    
    public Integer getExtensionDepth() {
        return extensionDepth;
    }
    
    public void setExtensionDepth(Integer extensionDepth) {
        this.extensionDepth = extensionDepth;
    }
}



