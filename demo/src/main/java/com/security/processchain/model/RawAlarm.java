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
    private String hostName;
    private String processGuid;
    private String parentProcessGuid;
    private String threatSeverity;
    private Integer severity; // 告警严重程度（数字）
    private String startTime;
    private String endTime;
    private String deviceAssetSubType;
    private String alarmName;
    private String logType;
    private String opType;
    
    // 进程相关字段
    private String processName;
    private Integer processId;
    private String image;
    private String commandLine;
    private String processMd5;
    private String processUserName;
    
    // 父进程相关字段（用于创建虚拟父节点）
    private String parentProcessName;
    private Integer parentProcessId;
    private String parentImage;
    private String parentCommandLine;
    private String parentProcessMd5;
    private String parentProcessUserName;
    
    // 文件相关字段
    private String fileName;
    private String fileMd5;
    private String targetFilename;
    
    // 域名相关字段
    private String requestDomain;
    
    // 网络相关字段
    private String srcAddress;
    private String srcPort;
    private String destAddress;
    private String destPort;
    
    // 注册表相关字段
    private String targetObject;
    private String regValue;
    
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
    
    public String getOpType() {
        return opType;
    }
    
    public void setOpType(String opType) {
        this.opType = opType;
    }
    
    public Map<String, Object> getOtherFields() {
        return otherFields;
    }
    
    public void setOtherFields(Map<String, Object> otherFields) {
        this.otherFields = otherFields;
    }
    
    public String getHostName() {
        return hostName;
    }
    
    public void setHostName(String hostName) {
        this.hostName = hostName;
    }
    
    public Integer getSeverity() {
        return severity;
    }
    
    public void setSeverity(Integer severity) {
        this.severity = severity;
    }
    
    public String getProcessName() {
        return processName;
    }
    
    public void setProcessName(String processName) {
        this.processName = processName;
    }
    
    public Integer getProcessId() {
        return processId;
    }
    
    public void setProcessId(Integer processId) {
        this.processId = processId;
    }
    
    public String getImage() {
        return image;
    }
    
    public void setImage(String image) {
        this.image = image;
    }
    
    public String getCommandLine() {
        return commandLine;
    }
    
    public void setCommandLine(String commandLine) {
        this.commandLine = commandLine;
    }
    
    public String getProcessMd5() {
        return processMd5;
    }
    
    public void setProcessMd5(String processMd5) {
        this.processMd5 = processMd5;
    }
    
    public String getProcessUserName() {
        return processUserName;
    }
    
    public void setProcessUserName(String processUserName) {
        this.processUserName = processUserName;
    }
    
    public String getParentProcessName() {
        return parentProcessName;
    }
    
    public void setParentProcessName(String parentProcessName) {
        this.parentProcessName = parentProcessName;
    }
    
    public Integer getParentProcessId() {
        return parentProcessId;
    }
    
    public void setParentProcessId(Integer parentProcessId) {
        this.parentProcessId = parentProcessId;
    }
    
    public String getParentImage() {
        return parentImage;
    }
    
    public void setParentImage(String parentImage) {
        this.parentImage = parentImage;
    }
    
    public String getParentCommandLine() {
        return parentCommandLine;
    }
    
    public void setParentCommandLine(String parentCommandLine) {
        this.parentCommandLine = parentCommandLine;
    }
    
    public String getParentProcessMd5() {
        return parentProcessMd5;
    }
    
    public void setParentProcessMd5(String parentProcessMd5) {
        this.parentProcessMd5 = parentProcessMd5;
    }
    
    public String getParentProcessUserName() {
        return parentProcessUserName;
    }
    
    public void setParentProcessUserName(String parentProcessUserName) {
        this.parentProcessUserName = parentProcessUserName;
    }
    
    public String getFileName() {
        return fileName;
    }
    
    public void setFileName(String fileName) {
        this.fileName = fileName;
    }
    
    public String getFileMd5() {
        return fileMd5;
    }
    
    public void setFileMd5(String fileMd5) {
        this.fileMd5 = fileMd5;
    }
    
    public String getTargetFilename() {
        return targetFilename;
    }
    
    public void setTargetFilename(String targetFilename) {
        this.targetFilename = targetFilename;
    }
    
    public String getRequestDomain() {
        return requestDomain;
    }
    
    public void setRequestDomain(String requestDomain) {
        this.requestDomain = requestDomain;
    }
    
    public String getSrcAddress() {
        return srcAddress;
    }
    
    public void setSrcAddress(String srcAddress) {
        this.srcAddress = srcAddress;
    }
    
    public String getSrcPort() {
        return srcPort;
    }
    
    public void setSrcPort(String srcPort) {
        this.srcPort = srcPort;
    }
    
    public String getDestAddress() {
        return destAddress;
    }
    
    public void setDestAddress(String destAddress) {
        this.destAddress = destAddress;
    }
    
    public String getDestPort() {
        return destPort;
    }
    
    public void setDestPort(String destPort) {
        this.destPort = destPort;
    }
    
    public String getTargetObject() {
        return targetObject;
    }
    
    public void setTargetObject(String targetObject) {
        this.targetObject = targetObject;
    }
    
    public String getRegValue() {
        return regValue;
    }
    
    public void setRegValue(String regValue) {
        this.regValue = regValue;
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



