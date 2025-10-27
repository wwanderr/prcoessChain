package com.security.processchain.service;

/**
 * 进程实体
 */
public class ProcessEntity {
    private String opType;
    private String localtime;
    private String processId;
    private String processGuid;
    private String parentProcessGuid;
    private String image;
    private String commandline;
    private String processUserName;
    private String processName;
    
    public ProcessEntity() {}
    
    public String getOpType() {
        return opType;
    }
    
    public void setOpType(String opType) {
        this.opType = opType;
    }
    
    public String getLocaltime() {
        return localtime;
    }
    
    public void setLocaltime(String localtime) {
        this.localtime = localtime;
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
    
    public String getCommandline() {
        return commandline;
    }
    
    public void setCommandline(String commandline) {
        this.commandline = commandline;
    }
    
    public String getProcessUserName() {
        return processUserName;
    }
    
    public void setProcessUserName(String processUserName) {
        this.processUserName = processUserName;
    }
    
    public String getProcessName() {
        return processName;
    }
    
    public void setProcessName(String processName) {
        this.processName = processName;
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
}



