package com.security.processchain.util;

import com.security.processchain.model.RawAlarm;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * 告警选举工具类
 * 实现选举算法,从多个告警组中选出最严重的组
 */
@Slf4j
public class AlarmElectionUtil {
    /**
     * 告警选举：按 alarmName 去重后选择数量最多的 traceId
     * 
     * 新规则：
     * 1. 对每个 traceId 的告警，按 alarmName 去重
     * 2. 选择去重后数量最多的 traceId
     * 3. 如果有多个 traceId 数量相同（并列第一），随机选一个
     *
     * @param alarmGroups 按traceId分组的告警
     * @return 被选中的traceId，若无可选则返回null
     */
    public static String electAlarm(Map<String, List<RawAlarm>> alarmGroups) {
        if (alarmGroups == null || alarmGroups.isEmpty()) {
            return null;
        }

        try {
            // 过滤空组
            Map<String, List<RawAlarm>> validGroups = new HashMap<>();
            for (Map.Entry<String, List<RawAlarm>> entry : alarmGroups.entrySet()) {
                if (entry.getValue() != null && !entry.getValue().isEmpty()) {
                    validGroups.put(entry.getKey(), entry.getValue());
                }
            }

            if (validGroups.isEmpty()) {
                return null;
            }

            if (validGroups.size() == 1) {
                return validGroups.keySet().iterator().next();
            }

            // ✅ 新逻辑：统计每个 traceId 的唯一 alarmName 数量和威胁统计
            Map<String, Integer> traceIdToUniqueAlarmNameCount = new HashMap<>();
            Map<String, ThreatStatistics> traceIdToThreatStats = new HashMap<>();
            
            for (Map.Entry<String, List<RawAlarm>> entry : validGroups.entrySet()) {
                String traceId = entry.getKey();
                List<RawAlarm> alarms = entry.getValue();
                
                // 统计该 traceId 下的唯一 alarmName
                Set<String> uniqueAlarmNames = new HashSet<>();
                for (RawAlarm alarm : alarms) {
                    if (alarm != null && alarm.getAlarmName() != null && !alarm.getAlarmName().trim().isEmpty()) {
                        uniqueAlarmNames.add(alarm.getAlarmName().trim());
                    }
                }
                
                // 计算威胁统计
                ThreatStatistics stats = calculateThreatStatistics(alarms);
                
                traceIdToUniqueAlarmNameCount.put(traceId, uniqueAlarmNames.size());
                traceIdToThreatStats.put(traceId, stats);
                
                log.debug("【告警选举】traceId={}, 唯一alarmName数量={}, 威胁统计={}", 
                         traceId, uniqueAlarmNames.size(), stats);
            }
            
            // ✅ 找出唯一 alarmName 数量最多的 traceId
            int maxCount = 0;
            List<String> bestTraceIds = new ArrayList<>();
            
            for (Map.Entry<String, Integer> entry : traceIdToUniqueAlarmNameCount.entrySet()) {
                int count = entry.getValue();
                if (count > maxCount) {
                    maxCount = count;
                    bestTraceIds.clear();
                    bestTraceIds.add(entry.getKey());
                } else if (count == maxCount) {
                    bestTraceIds.add(entry.getKey());
                }
            }
            
            if (bestTraceIds.isEmpty()) {
                log.warn("【告警选举】未找到有效的 traceId");
                return null;
            }
            
            // ✅ 如果有多个 traceId 并列第一（alarmName 数量相同）
            String selectedTraceId;
            if (bestTraceIds.size() == 1) {
                selectedTraceId = bestTraceIds.get(0);
                log.info("【告警选举】选中 traceId={}, 唯一alarmName数量={}", selectedTraceId, maxCount);
            } else {
                // ✅ 按威胁等级选择（高危最多的）
                log.info("【告警选举】多个 traceId 并列（alarmName数量={}），按威胁等级选择", maxCount);
                
                String bestTraceId = null;
                ThreatStatistics bestStats = null;
                
                for (String traceId : bestTraceIds) {
                    ThreatStatistics stats = traceIdToThreatStats.get(traceId);
                    if (bestStats == null || compareThreatStatistics(stats, bestStats) > 0) {
                        bestStats = stats;
                        bestTraceId = traceId;
                    }
                }
                
                selectedTraceId = bestTraceId;
                log.info("【告警选举】按威胁等级选中: traceId={}, 威胁统计={}, 候选列表={}", 
                        selectedTraceId, bestStats, bestTraceIds);
            }
            
            return selectedTraceId;
            
        } catch (Exception e) {
            log.error("告警选举过程异常: {}", e.getMessage(), e);
            return null;
        }
    }
    
    /**
     * 从多个告警组中选举出最优的一个组
     * 
     * @param alarmGroups 按traceId分组的告警组
     * @return 选举出的最优告警组,如果输入为空或异常则返回空列表
     */
    public static List<RawAlarm> electBestAlarmGroup(Map<String, List<RawAlarm>> alarmGroups) {
        if (alarmGroups == null || alarmGroups.isEmpty()) {
            log.info("告警选举: 告警组为空");
            return new ArrayList<>();
        }
        
        try {
            // 过滤掉空的告警组
            Map<String, List<RawAlarm>> validGroups = new HashMap<>();
            for (Map.Entry<String, List<RawAlarm>> entry : alarmGroups.entrySet()) {
                if (entry.getValue() != null && !entry.getValue().isEmpty()) {
                    validGroups.put(entry.getKey(), entry.getValue());
                }
            }
            
            if (validGroups.isEmpty()) {
                log.info("告警选举: 所有告警组都为空");
                return new ArrayList<>();
            }
            
            if (validGroups.size() == 1) {
                String singleKey = validGroups.keySet().iterator().next();
                log.info("告警选举: 只有一个告警组, traceId={}", singleKey);
                return validGroups.get(singleKey);
            }
            
            // 计算每个组的威胁等级统计
            Map<String, ThreatStatistics> groupStats = new HashMap<>();
            for (Map.Entry<String, List<RawAlarm>> entry : validGroups.entrySet()) {
                try {
                    ThreatStatistics stats = calculateThreatStatistics(entry.getValue());
                    groupStats.put(entry.getKey(), stats);
                } catch (Exception e) {
                    log.warn("计算告警组统计失败, traceId={}, 错误: {}", entry.getKey(), e.getMessage());
                }
            }
            
            if (groupStats.isEmpty()) {
                log.error("所有告警组统计计算失败");
                return new ArrayList<>();
            }
            
            // 选举最优组
            String bestGroupKey = null;
            ThreatStatistics bestStats = null;
            
            for (Map.Entry<String, ThreatStatistics> entry : groupStats.entrySet()) {
                if (bestStats == null || compareThreatStatistics(entry.getValue(), bestStats) > 0) {
                    bestStats = entry.getValue();
                    bestGroupKey = entry.getKey();
                }
            }
            
            if (bestGroupKey == null) {
                log.error("选举失败，未找到最优告警组");
                return new ArrayList<>();
            }
            
            log.info("告警选举: 选中告警组 traceId={}, 统计={}", bestGroupKey, bestStats);
            return validGroups.get(bestGroupKey);
            
        } catch (Exception e) {
            log.error("告警选举过程异常: {}", e.getMessage(), e);
            return new ArrayList<>();
        }
    }
    
    /**
     * 计算告警组的威胁等级统计
     * 
     * @param alarms 告警列表
     * @return 威胁统计结果
     */
    private static ThreatStatistics calculateThreatStatistics(List<RawAlarm> alarms) {
        ThreatStatistics stats = new ThreatStatistics();
        
        if (alarms == null || alarms.isEmpty()) {
            return stats;
        }
        
        for (RawAlarm alarm : alarms) {
            if (alarm == null) {
                continue;
            }
            
            String severity = alarm.getThreatSeverity();
            if (severity == null || severity.trim().isEmpty()) {
                continue;
            }
            
            severity = severity.trim();
            
            if ("HIGH".equalsIgnoreCase(severity) || "高".equals(severity)) {
                stats.highCount++;
            } else if ("MEDIUM".equalsIgnoreCase(severity) || "中".equals(severity)) {
                stats.mediumCount++;
            } else if ("LOW".equalsIgnoreCase(severity) || "低".equals(severity)) {
                stats.lowCount++;
            }
        }
        
        return stats;
    }
    
    /**
     * 比较两个威胁统计
     * 
     * @return 正数表示stats1更优, 负数表示stats2更优, 0表示平局
     */
    private static int compareThreatStatistics(ThreatStatistics stats1, ThreatStatistics stats2) {
        // 第一优先级: 比较高危数量
        if (stats1.highCount != stats2.highCount) {
            return stats1.highCount - stats2.highCount;
        }
        
        // 第二优先级: 比较中危数量
        if (stats1.mediumCount != stats2.mediumCount) {
            return stats1.mediumCount - stats2.mediumCount;
        }
        
        // 第三优先级: 比较低危数量
        if (stats1.lowCount != stats2.lowCount) {
            return stats1.lowCount - stats2.lowCount;
        }
        
        // 完全相同,平局
        return 0;
    }
    
    /**
     * 威胁统计内部类
     */
    private static class ThreatStatistics {
        int highCount = 0;
        int mediumCount = 0;
        int lowCount = 0;
        
        @Override
        public String toString() {
            return "ThreatStatistics{" +
                    "high=" + highCount +
                    ", medium=" + mediumCount +
                    ", low=" + lowCount +
                    '}';
        }
    }
}

