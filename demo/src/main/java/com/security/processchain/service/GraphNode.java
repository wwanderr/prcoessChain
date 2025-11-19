package com.security.processchain.service;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/**
 * 图节点
 * 
 * 表示进程链图中的一个节点，可以是：
 * - 进程节点（process）
 * - 实体节点（file_entity, domain_entity, network_entity, registry_entity）
 */
@Getter
@Setter
public class GraphNode {
    private String nodeId;
    private String parentProcessGuid;
    private String traceId;
    private String hostAddress;
    
    private List<RawAlarm> alarms;
    private List<RawLog> logs;
    
    private boolean isRoot;
    private boolean isBroken;
    private boolean isAlarm;
    private boolean isVirtual;  // 是否是虚拟节点（拆分产生的）
    
    private String nodeType;  // process/file/domain/network/registry/entity
    
    public GraphNode() {
        this.alarms = new ArrayList<>();
        this.logs = new ArrayList<>();
    }
    
    // 特殊的 Setter 方法（带业务逻辑）
    public void setAlarms(List<RawAlarm> alarms) { 
        this.alarms = alarms != null ? alarms : new ArrayList<>();
        this.isAlarm = !this.alarms.isEmpty();
    }
    
    public void addAlarm(RawAlarm alarm) { 
        if (alarm != null) {
            this.alarms.add(alarm);
            this.isAlarm = true;
        }
    }
    
    public void setLogs(List<RawLog> logs) { 
        this.logs = logs != null ? logs : new ArrayList<>();
    }
    
    public void addLog(RawLog log) { 
        if (log != null) {
            this.logs.add(log);
        }
    }
}

