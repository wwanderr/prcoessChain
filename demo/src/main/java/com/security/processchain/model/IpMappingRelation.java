package com.security.processchain.model;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * IP映射关系数据结构
 * 包含端侧IP、网端关联关系、告警ID映射、日志ID映射
 */
public class IpMappingRelation {
    
    /**
     * 端侧（受害者）的节点
     * key: 端侧IP
     * value: 是否网端关联
     */
    private Map<String, Boolean> ipAndAssociation;
    
    /**
     * 落盘时记录的强关联的IP和原始告警ID的映射
     * key: 网端关联的IP
     * value: 原始告警ID（eventId）
     */
    private Map<String, String> alarmIps;
    
    /**
     * 强关联时IP和原始日志ID的映射
     * key: IP
     * value: 日志ID
     */
    private Map<String, String> logs;
    
    /**
     * 端侧受害者IP和traceId的映射（新增）
     * 用于无告警场景：通过IP获取traceId去查询日志
     * key: 端侧IP (hostAddress)
     * value: traceId
     */
    private Map<String, String> ipToTraceIds;
    
    public IpMappingRelation() {
        this.ipAndAssociation = new HashMap<>();
        this.alarmIps = new HashMap<>();
        this.logs = new HashMap<>();
        this.ipToTraceIds = new HashMap<>();
    }
    
    /**
     * 获取所有IP列表
     */
    public List<String> getAllIps() {
        return new java.util.ArrayList<>(ipAndAssociation.keySet());
    }
    
    /**
     * 判断IP是否有网端关联
     */
    public boolean hasAssociation(String ip) {
        Boolean association = ipAndAssociation.get(ip);
        return association != null && association;
    }
    
    /**
     * 获取IP对应的关联告警ID
     */
    public String getAssociatedEventId(String ip) {
        if (hasAssociation(ip)) {
            return alarmIps.get(ip);
        }
        return null;
    }
    
    /**
     * 获取IP对应的日志ID
     */
    public String getLogId(String ip) {
        return logs != null ? logs.get(ip) : null;
    }
    
    /**
     * 获取既在ipAndAssociation中，又在alarmIps中的IP及其对应的告警ID映射
     * 即：网端关联且有告警ID的IP
     * 
     * @return Map<IP, 告警ID>
     */
    public Map<String, String> getIpsInAlarmIps() {
        Map<String, String> result = new HashMap<>();
        
        if (ipAndAssociation == null || ipAndAssociation.isEmpty() || 
            alarmIps == null || alarmIps.isEmpty()) {
            return result;
        }
        
        for (String ip : ipAndAssociation.keySet()) {
            // 检查是否在alarmIps中
            if (alarmIps.containsKey(ip)) {
                result.put(ip, alarmIps.get(ip));
            }
        }
        
        return result;
    }
    
    /**
     * 获取既在ipAndAssociation中，又在logs中的IP及其对应的告警ID映射
     * 
     * @return Map<IP, 告警ID>，告警ID从alarmIps中获取，如果没有则为null
     */
    public Map<String, String> getIpsInLogs() {
        Map<String, String> result = new HashMap<>();
        
        if (ipAndAssociation == null || ipAndAssociation.isEmpty() || 
            logs == null || logs.isEmpty()) {
            return result;
        }
        
        for (String ip : ipAndAssociation.keySet()) {
            // 检查是否在logs中且有日志ID
            if (logs.containsKey(ip)) {
                String logId = logs.get(ip);
                if (logId != null && !logId.trim().isEmpty()) {
                    // 从alarmIps中获取告警ID（如果有）
                    String alarmId = (alarmIps != null) ? alarmIps.get(ip) : null;
                    result.put(ip, alarmId);
                }
            }
        }
        
        return result;
    }

    // Getters and Setters
    
    public Map<String, Boolean> getIpAndAssociation() {
        return ipAndAssociation;
    }

    public void setIpAndAssociation(Map<String, Boolean> ipAndAssociation) {
        this.ipAndAssociation = (ipAndAssociation != null) ? ipAndAssociation : new HashMap<>();
    }

    public Map<String, String> getAlarmIps() {
        return alarmIps;
    }

    public void setAlarmIps(Map<String, String> alarmIps) {
        this.alarmIps = (alarmIps != null) ? alarmIps : new HashMap<>();
    }
    
    public Map<String, String> getLogs() {
        return logs;
    }
    
    public void setLogs(Map<String, String> logs) {
        this.logs = (logs != null) ? logs : new HashMap<>();
    }
    
    public Map<String, String> getIpToTraceIds() {
        return ipToTraceIds;
    }
    
    public void setIpToTraceIds(Map<String, String> ipToTraceIds) {
        this.ipToTraceIds = (ipToTraceIds != null) ? ipToTraceIds : new HashMap<>();
    }


    @Override
    public String toString() {
        return "IpMappingRelation{" +
                "ipCount=" + (ipAndAssociation != null ? ipAndAssociation.size() : 0) +
                ", associatedCount=" + (alarmIps != null ? alarmIps.size() : 0) +
                ", logsCount=" + (logs != null ? logs.size() : 0) +
                ", ipToTraceIdsCount=" + (ipToTraceIds != null ? ipToTraceIds.size() : 0) +
                '}';
    }
}

