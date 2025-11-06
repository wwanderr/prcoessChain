package com.security.processchain.service;

/**
 * 告警节点信息
 */
public class AlarmNodeInfo {
    private String alarmName;
    private String dvcAction;
    private String alarmDescription;
    private String alarmSource;
    private ThreatSeverity threatSeverity;
    private String alarmResults;
    
    public AlarmNodeInfo() {
        this.alarmName = "";
        this.dvcAction = "";
        this.alarmDescription = "";
        this.alarmSource = "";
        this.alarmResults = "";
    }
    
    public String getAlarmName() {
        return alarmName;
    }
    
    public void setAlarmName(String alarmName) {
        this.alarmName = alarmName;
    }
    
    public String getDvcAction() {
        return dvcAction;
    }
    
    public void setDvcAction(String dvcAction) {
        this.dvcAction = dvcAction;
    }
    
    public String getAlarmDescription() {
        return alarmDescription;
    }
    
    public void setAlarmDescription(String alarmDescription) {
        this.alarmDescription = alarmDescription;
    }
    
    public String getAlarmSource() {
        return alarmSource;
    }
    
    public void setAlarmSource(String alarmSource) {
        this.alarmSource = alarmSource;
    }
    
    public ThreatSeverity getThreatSeverity() {
        return threatSeverity;
    }
    
    public void setThreatSeverity(ThreatSeverity threatSeverity) {
        this.threatSeverity = threatSeverity;
    }
    
    public String getAlarmResults() {
        return alarmResults;
    }
    
    public void setAlarmResults(String alarmResults) {
        this.alarmResults = alarmResults;
    }
}



