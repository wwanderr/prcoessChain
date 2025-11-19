package com.security.processchain.service;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/**
 * 进程节点内部类
 * 优化版本：添加了 traceId、hostAddress、isRoot、isBroken、importance 字段
 * 减少了后续查找和判断的开销
 */
@Getter
@Setter
public class ChainBuilderNode {
    private String processGuid;
    private String parentProcessGuid;
    private Boolean isAlarm = false;
    private List<RawAlarm> alarms = new ArrayList<>();
    private List<RawLog> logs = new ArrayList<>();
    
    // ========== 优化新增字段 ==========
    // traceId: 节点所属的溯源ID，避免重复从alarms/logs中提取
    private String traceId;
    
    // hostAddress: 节点所属的主机IP，避免重复从alarms/logs中提取
    private String hostAddress;
    
    // isRoot: 是否为根节点，避免重复判断 parentProcessGuid
    private Boolean isRoot = false;
    
    // isBroken: 是否为断链节点，避免重复查找 brokenNodes 集合
    private Boolean isBroken = false;
    
    // importance: 节点重要性分数，用于裁剪时快速判断
    private Double importance = 0.0;
    
    // nodeType: 节点类型，用于区分进程节点和实体节点
    // 可能的值："process", "file_entity", "domain_entity", "network_entity", "registry_entity"
    private String nodeType;
    
    // 特殊方法（带业务逻辑）
    public void addAlarm(RawAlarm alarm) {
        this.alarms.add(alarm);
        this.isAlarm = true;
        // 优化：添加告警时自动提取 traceId 和 hostAddress
        if (alarm != null) {
            if (this.traceId == null && alarm.getTraceId() != null) {
                this.traceId = alarm.getTraceId();
            }
            if (this.hostAddress == null && alarm.getHostAddress() != null) {
                this.hostAddress = alarm.getHostAddress();
            }
        }
    }
    
    public void addLog(RawLog log) {
        this.logs.add(log);
        // 优化：添加日志时自动提取 traceId 和 hostAddress
        if (log != null) {
            if (this.traceId == null && log.getTraceId() != null) {
                this.traceId = log.getTraceId();
            }
            if (this.hostAddress == null && log.getHostAddress() != null) {
                this.hostAddress = log.getHostAddress();
            }
        }
    }
}

