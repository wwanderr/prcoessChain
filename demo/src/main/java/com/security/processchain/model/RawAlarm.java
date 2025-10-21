package com.security.processchain.model;

import java.util.Map;

/**
 * 原始告警数据模型
 * 对应ES中的告警数据
 */
public class RawAlarm {
    private String eventId;
    private String traceId;
    private String hostAddress;
    private String processGuid;
    private String parentProcessGuid;
    private String threatSeverity;
    private String startTime;
    private String endTime;
    private String deviceAssetSubType;
    private String alarmName;
    private String logType;
    
    // 其他字段
    private Map<String, Object> otherFields;
    
    public RawAlarm() {}
    
    // Getters and Setters
    public String getEventId() {
        return eventId;
    }
    
    public void setEventId(String eventId) {
        this.eventId = eventId;
    }
    
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
    
    public String getProcessGuid() {
        return processGuid;
    }
    
    public void setProcessGuid(String processGuid) {
        this.processGuid = processGuid;
    }
    
    public String getParentProcessGuid() {
        return parentProcessGuid;
    }
    
    public void setParentProcessGuid(String parentProcessGuid) {
        this.parentProcessGuid = parentProcessGuid;
    }
    
    public String getThreatSeverity() {
        return threatSeverity;
    }
    
    public void setThreatSeverity(String threatSeverity) {
        this.threatSeverity = threatSeverity;
    }
    
    public String getStartTime() {
        return startTime;
    }
    
    public void setStartTime(String startTime) {
        this.startTime = startTime;
    }
    
    public String getEndTime() {
        return endTime;
    }
    
    public void setEndTime(String endTime) {
        this.endTime = endTime;
    }
    
    public String getDeviceAssetSubType() {
        return deviceAssetSubType;
    }
    
    public void setDeviceAssetSubType(String deviceAssetSubType) {
        this.deviceAssetSubType = deviceAssetSubType;
    }
    
    public String getAlarmName() {
        return alarmName;
    }
    
    public void setAlarmName(String alarmName) {
        this.alarmName = alarmName;
    }
    
    public String getLogType() {
        return logType;
    }
    
    public void setLogType(String logType) {
        this.logType = logType;
    }
    
    public Map<String, Object> getOtherFields() {
        return otherFields;
    }
    
    public void setOtherFields(Map<String, Object> otherFields) {
        this.otherFields = otherFields;
    }
    
    @Override
    public String toString() {
        return "RawAlarm{" +
                "eventId='" + eventId + '\'' +
                ", traceId='" + traceId + '\'' +
                ", hostAddress='" + hostAddress + '\'' +
                ", processGuid='" + processGuid + '\'' +
                ", threatSeverity='" + threatSeverity + '\'' +
                '}';
    }
}



