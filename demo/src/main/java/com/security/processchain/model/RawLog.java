package com.security.processchain.model;

import java.util.Map;

/**
 * 原始日志数据模型
 * 对应ES中的日志数据
 */
public class RawLog {
    private String eventId;
    private String traceId;
    private String hostAddress;
    private String processGuid;
    private String parentProcessGuid;
    private String logType;
    private String startTime;
    
    // 进程相关字段
    private String processName;
    private String processId;
    private String image;
    private String commandLine;
    private String processUserName;
    private String opType;
    
    // 文件相关字段
    private String fileName;
    private String filePath;
    private String fileMd5;
    private String fileSize;
    private String fileType;
    private String targetFilename;
    
    // 网络相关字段
    private String transProtocol;
    private String srcAddress;
    private String srcPort;
    private String destAddress;
    private String destPort;
    private String initiated;
    
    // 域名相关字段
    private String requestDomain;
    private String queryResults;
    
    // 其他字段
    private Map<String, Object> otherFields;
    
    public RawLog() {}
    
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
    
    public String getLogType() {
        return logType;
    }
    
    public void setLogType(String logType) {
        this.logType = logType;
    }
    
    public String getStartTime() {
        return startTime;
    }
    
    public void setStartTime(String startTime) {
        this.startTime = startTime;
    }
    
    public String getProcessName() {
        return processName;
    }
    
    public void setProcessName(String processName) {
        this.processName = processName;
    }
    
    public String getProcessId() {
        return processId;
    }
    
    public void setProcessId(String processId) {
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
    
    public String getProcessUserName() {
        return processUserName;
    }
    
    public void setProcessUserName(String processUserName) {
        this.processUserName = processUserName;
    }
    
    public String getOpType() {
        return opType;
    }
    
    public void setOpType(String opType) {
        this.opType = opType;
    }
    
    public String getFileName() {
        return fileName;
    }
    
    public void setFileName(String fileName) {
        this.fileName = fileName;
    }
    
    public String getFilePath() {
        return filePath;
    }
    
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }
    
    public String getFileMd5() {
        return fileMd5;
    }
    
    public void setFileMd5(String fileMd5) {
        this.fileMd5 = fileMd5;
    }
    
    public String getFileSize() {
        return fileSize;
    }
    
    public void setFileSize(String fileSize) {
        this.fileSize = fileSize;
    }
    
    public String getFileType() {
        return fileType;
    }
    
    public void setFileType(String fileType) {
        this.fileType = fileType;
    }
    
    public String getTargetFilename() {
        return targetFilename;
    }
    
    public void setTargetFilename(String targetFilename) {
        this.targetFilename = targetFilename;
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
    
    public String getInitiated() {
        return initiated;
    }
    
    public void setInitiated(String initiated) {
        this.initiated = initiated;
    }
    
    public String getRequestDomain() {
        return requestDomain;
    }
    
    public void setRequestDomain(String requestDomain) {
        this.requestDomain = requestDomain;
    }
    
    public String getQueryResults() {
        return queryResults;
    }
    
    public void setQueryResults(String queryResults) {
        this.queryResults = queryResults;
    }
    
    public Map<String, Object> getOtherFields() {
        return otherFields;
    }
    
    public void setOtherFields(Map<String, Object> otherFields) {
        this.otherFields = otherFields;
    }
}



