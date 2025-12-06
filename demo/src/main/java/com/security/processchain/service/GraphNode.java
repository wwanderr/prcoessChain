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
    private String processGuid;
    private String parentProcessGuid;
    private String traceId;
    private String hostAddress;
    private String hostName;
    
    // 进程相关字段
    private String processName;
    private Integer processId;
    private String image;
    private String commandLine;
    private String processMd5;
    private String processUserName;
    
    private List<RawAlarm> alarms;
    private List<RawLog> logs;
    
    private boolean isRoot;
    private boolean isBroken;
    private boolean isAlarm;
    private boolean isVirtual;  // 是否是虚拟节点（拆分产生的）
    
    /**
     * 日志数量是否已达上限（性能优化标志位）
     * 用于避免在建图阶段重复检查和打印警告
     */
    private boolean logLimitReached = false;
    
    private String nodeType;  // process/file/domain/network/registry/entity
    
    /**
     * 创建该实体节点的事件ID
     * 用于网端关联标识时精确匹配
     * 只对实体节点有效，进程节点为null
     */
    private String createdByEventId;
    
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

