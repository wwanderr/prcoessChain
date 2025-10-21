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
}



