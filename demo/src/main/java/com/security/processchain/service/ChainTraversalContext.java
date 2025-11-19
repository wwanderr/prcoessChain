package com.security.processchain.service;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import lombok.Getter;

import java.util.*;

/**
 * 链遍历上下文
 * 封装构建过程中需要的所有索引和配置
 */
@Getter
public class ChainTraversalContext {
    // 日志索引
    private final Map<String, List<RawLog>> logsByProcessGuid;
    private final Map<String, List<RawLog>> logsByParentProcessGuid;
    
    // 告警索引
    private final Map<String, List<RawAlarm>> alarmsByProcessGuid;
    private final Map<String, List<RawAlarm>> alarmsByParentProcessGuid;
    
    // 溯源配置
    private final Set<String> traceIds;
    
    public ChainTraversalContext(
            Map<String, List<RawLog>> logsByProcessGuid,
            Map<String, List<RawLog>> logsByParentProcessGuid,
            Map<String, List<RawAlarm>> alarmsByProcessGuid,
            Map<String, List<RawAlarm>> alarmsByParentProcessGuid,
            Set<String> traceIds) {
        this.logsByProcessGuid = logsByProcessGuid != null ? logsByProcessGuid : new HashMap<>();
        this.logsByParentProcessGuid = logsByParentProcessGuid != null ? logsByParentProcessGuid : new HashMap<>();
        this.alarmsByProcessGuid = alarmsByProcessGuid != null ? alarmsByProcessGuid : new HashMap<>();
        this.alarmsByParentProcessGuid = alarmsByParentProcessGuid != null ? alarmsByParentProcessGuid : new HashMap<>();
        this.traceIds = traceIds != null ? traceIds : new HashSet<>();
    }
    
    /**
     * 检查父节点是否存在（日志或告警）
     */
    public boolean hasParentNode(String parentProcessGuid) {
        if (parentProcessGuid == null || parentProcessGuid.isEmpty()) {
            return false;
        }
        return logsByProcessGuid.containsKey(parentProcessGuid) ||
               alarmsByProcessGuid.containsKey(parentProcessGuid);
    }
    
    /**
     * 获取父节点日志（如果存在）
     */
    public List<RawLog> getParentLogs(String parentProcessGuid) {
        return logsByProcessGuid.get(parentProcessGuid);
    }
    
    /**
     * 获取父节点告警（如果存在）
     */
    public List<RawAlarm> getParentAlarms(String parentProcessGuid) {
        return alarmsByProcessGuid.get(parentProcessGuid);
    }
    
    /**
     * 获取子节点日志列表
     */
    public List<RawLog> getChildLogs(String processGuid) {
        return logsByParentProcessGuid.get(processGuid);
    }
    
    /**
     * 获取子节点告警列表
     */
    public List<RawAlarm> getChildAlarms(String processGuid) {
        return alarmsByParentProcessGuid.get(processGuid);
    }
    
    /**
     * 检查父节点是否在日志索引中
     */
    public boolean hasParentInLogs(String parentProcessGuid) {
        return parentProcessGuid != null && !parentProcessGuid.isEmpty() &&
               logsByProcessGuid.containsKey(parentProcessGuid);
    }
    
    /**
     * 检查父节点是否在告警索引中
     */
    public boolean hasParentInAlarms(String parentProcessGuid) {
        return parentProcessGuid != null && !parentProcessGuid.isEmpty() &&
               alarmsByProcessGuid.containsKey(parentProcessGuid);
    }
}

