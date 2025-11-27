package com.security.processchain.util;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 数据转换工具类
 * 将ES返回的Map<String, Object>转换为结构化对象
 */
public class DataConverter {
    
    /**
     * 将ES返回的hit数组转换为RawAlarm列表
     * 
     * @param hits ES查询返回的hit数组
     * @return RawAlarm列表
     */
    public static List<RawAlarm> convertToAlarmList(List<Map<String, Object>> hits) {
        List<RawAlarm> alarms = new ArrayList<>();
        
        if (hits == null || hits.isEmpty()) {
            return alarms;
        }
        
        for (Map<String, Object> hit : hits) {
            RawAlarm alarm = convertToAlarm(hit);
            if (alarm != null) {
                alarms.add(alarm);
            }
        }
        
        return alarms;
    }
    
    /**
     * 将单个Map转换为RawAlarm
     * 
     * @param map ES返回的单条数据
     * @return RawAlarm对象
     */
    public static RawAlarm convertToAlarm(Map<String, Object> map) {
        if (map == null) {
            return null;
        }
        
        RawAlarm alarm = new RawAlarm();
        
        // 基础字段
        alarm.setEventId(getStringValue(map, "eventId"));
        alarm.setTraceId(getStringValue(map, "traceId"));
        alarm.setHostAddress(getStringValue(map, "hostAddress"));
        alarm.setHostName(getStringValue(map, "hostName"));
        alarm.setProcessGuid(getStringValue(map, "processGuid"));
        alarm.setParentProcessGuid(getStringValue(map, "parentProcessGuid"));
        alarm.setThreatSeverity(getStringValue(map, "threatSeverity"));
        alarm.setSeverity(getIntegerValue(map, "severity"));
        alarm.setStartTime(getStringValue(map, "startTime"));
        alarm.setEndTime(getStringValue(map, "endTime"));
        alarm.setDeviceAssetSubType(getStringValue(map, "deviceAssetSubType"));
        alarm.setAlarmName(getStringValue(map, "alarmName"));
        alarm.setLogType(getStringValue(map, "logType"));
        alarm.setOpType(getStringValue(map, "opType"));
        
        // 进程相关字段
        alarm.setProcessName(getStringValue(map, "processName"));
        alarm.setProcessId(getIntegerValue(map, "processId"));
        alarm.setImage(getStringValue(map, "image"));
        alarm.setCommandLine(getStringValue(map, "commandLine"));
        alarm.setProcessMd5(getStringValue(map, "processMd5"));
        alarm.setProcessUserName(getStringValue(map, "processUserName"));
        
        // 父进程相关字段（用于创建虚拟父节点）
        alarm.setParentProcessName(getStringValue(map, "parentProcessName"));
        alarm.setParentProcessId(getIntegerValue(map, "parentProcessId"));
        alarm.setParentImage(getStringValue(map, "parentImage"));
        alarm.setParentCommandLine(getStringValue(map, "parentCommandLine"));
        alarm.setParentProcessMd5(getStringValue(map, "parentProcessMd5"));
        alarm.setParentProcessUserName(getStringValue(map, "parentProcessUserName"));
        
        // 文件相关字段
        alarm.setFileName(getStringValue(map, "fileName"));
        alarm.setFileMd5(getStringValue(map, "fileMd5"));
        alarm.setTargetFilename(getStringValue(map, "targetFilename"));
        alarm.setFileHash(getStringValue(map, "fileHash"));
        alarm.setFileContents(getStringValue(map, "fileContents"));
        alarm.setCreationUtcTime(getStringValue(map, "creationUtcTime"));
        alarm.setPreviousCreationUtcTime(getStringValue(map, "previousCreationUtcTime"));
        
        // 域名相关字段
        alarm.setRequestDomain(getStringValue(map, "requestDomain"));
        
        // 网络相关字段
        alarm.setSrcAddress(getStringValue(map, "srcAddress"));
        alarm.setSrcPort(getStringValue(map, "srcPort"));
        alarm.setSrcTransAddress(getStringValue(map, "srcTransAddress"));
        alarm.setDestAddress(getStringValue(map, "destAddress"));
        alarm.setDestPort(getStringValue(map, "destPort"));
        alarm.setDestHostName(getStringValue(map, "destHostName"));
        
        // Web攻击相关字段
        alarm.setRequestUrl(getStringValue(map, "requestUrl"));
        alarm.setResponseCode(getStringValue(map, "responseCode"));
        alarm.setAppProtocol(getStringValue(map, "appProtocol"));
        
        // 攻击相关字段（用于告警描述模板替换）
        alarm.setAttacker(getStringValue(map, "attacker"));
        alarm.setVictim(getStringValue(map, "victim"));
        
        // 事件相关字段
        alarm.setEventType(getStringValue(map, "eventType"));
        alarm.setEventNum(getStringValue(map, "eventNum"));
        alarm.setDeviceAddress(getStringValue(map, "deviceAddress"));
        
        // 进程相关字段（扩展）
        alarm.setSourceImage(getStringValue(map, "sourceImage"));
        alarm.setDestImage(getStringValue(map, "destImage"));
        alarm.setImageLoaded(getStringValue(map, "imageLoaded"));
        
        // 签名相关字段
        alarm.setSignature(getStringValue(map, "signature"));
        alarm.setCompany(getStringValue(map, "company"));
        
        // 访问相关字段
        alarm.setGrantedAccess(getStringValue(map, "grantedAccess"));
        alarm.setStartAddress(getStringValue(map, "startAddress"));
        
        // 注册表相关字段
        alarm.setTargetObject(getStringValue(map, "targetObject"));
        alarm.setRegValue(getStringValue(map, "regValue"));
        alarm.setRegNewName(getStringValue(map, "regNewName"));
        
        // 管道相关字段
        alarm.setPipeName(getStringValue(map, "pipeName"));
        
        // WMI相关字段
        alarm.setOperation(getStringValue(map, "operation"));
        alarm.setWmiType(getStringValue(map, "wmiType"));
        alarm.setWmiEventNamespace(getStringValue(map, "wmiEventNamespace"));
        alarm.setWmiName(getStringValue(map, "wmiName"));
        alarm.setWmiQuery(getStringValue(map, "wmiQuery"));
        alarm.setWmiDestination(getStringValue(map, "wmiDestination"));
        alarm.setWmiConsumer(getStringValue(map, "wmiConsumer"));
        alarm.setWmiFilter(getStringValue(map, "wmiFilter"));
        
        // 保存原始数据,便于后续扩展
        alarm.setOtherFields(map);
        
        return alarm;
    }
    
    /**
     * 将ES返回的hit数组转换为RawLog列表
     * 
     * @param hits ES查询返回的hit数组
     * @return RawLog列表
     */
    public static List<RawLog> convertToLogList(List<Map<String, Object>> hits) {
        List<RawLog> logs = new ArrayList<>();
        
        if (hits == null || hits.isEmpty()) {
            return logs;
        }
        
        for (Map<String, Object> hit : hits) {
            RawLog log = convertToLog(hit);
            if (log != null) {
                logs.add(log);
            }
        }
        
        return logs;
    }
    
    /**
     * 将单个Map转换为RawLog
     * 
     * @param map ES返回的单条数据
     * @return RawLog对象
     */
    public static RawLog convertToLog(Map<String, Object> map) {
        if (map == null) {
            return null;
        }
        
        RawLog log = new RawLog();
        
        // 基础字段
        log.setEventId(getStringValue(map, "eventId"));
        log.setTraceId(getStringValue(map, "traceId"));
        log.setHostAddress(getStringValue(map, "hostAddress"));
        log.setProcessGuid(getStringValue(map, "processGuid"));
        log.setParentProcessGuid(getStringValue(map, "parentProcessGuid"));
        log.setLogType(getStringValue(map, "logType"));
        log.setStartTime(getStringValue(map, "startTime"));
        
        // 进程相关字段
        log.setEventType(getStringValue(map, "eventType"));
        log.setProcessName(getStringValue(map, "processName"));
        log.setProcessId(getIntegerValue(map, "processId"));
        log.setImage(getStringValue(map, "image"));
        log.setCommandLine(getStringValue(map, "commandLine"));
        log.setProcessUserName(getStringValue(map, "processUserName"));
        log.setOpType(getStringValue(map, "opType"));
        
        // 父进程相关字段（用于创建虚拟父节点）
        log.setParentProcessName(getStringValue(map, "parentProcessName"));
        log.setParentProcessId(getIntegerValue(map, "parentProcessId"));
        log.setParentImage(getStringValue(map, "parentImage"));
        log.setParentCommandLine(getStringValue(map, "parentCommandLine"));
        log.setParentProcessUserName(getStringValue(map, "parentProcessUserName"));
        
        // 文件相关字段
        log.setFileName(getStringValue(map, "fileName"));
        log.setFilePath(getStringValue(map, "filePath"));
        log.setFileMd5(getStringValue(map, "fileMd5"));
        log.setFileSize(getStringValue(map, "fileSize"));
        log.setFileType(getStringValue(map, "fileType"));
        log.setTargetFilename(getStringValue(map, "targetFilename"));
        
        // 网络相关字段
        log.setTransProtocol(getStringValue(map, "transProtocol"));
        log.setSrcAddress(getStringValue(map, "srcAddress"));
        log.setSrcPort(getStringValue(map, "srcPort"));
        log.setDestAddress(getStringValue(map, "destAddress"));
        log.setDestPort(getStringValue(map, "destPort"));
        log.setInitiated(getStringValue(map, "initiated"));
        
        // 域名相关字段
        log.setRequestDomain(getStringValue(map, "requestDomain"));
        log.setQueryResults(getStringValue(map, "queryResults"));
        
          // 注册表相关字段
        log.setTargetObject(getStringValue(map, "targetObject"));
        log.setRegValue(getStringValue(map, "regValue"));
        
        // 保存原始数据
        log.setOtherFields(map);
        
        return log;
    }
    
    /**
     * 安全获取String类型的值
     * 防止NPE和类型转换异常
     * 
     * @param map 数据Map
     * @param key 键
     * @return 字符串值,如果不存在或为null则返回null
     */
    private static String getStringValue(Map<String, Object> map, String key) {
        if (map == null || key == null) {
            return null;
        }
        
        try {
            Object value = map.get(key);
            if (value == null) {
                return null;
            }
            return value.toString();
        } catch (Exception e) {
            // 防止toString()方法抛出异常
            System.err.println("警告: 获取字段 [" + key + "] 值时异常: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 安全获取Integer类型的值
     * 
     * @param map 数据Map
     * @param key 键
     * @return Integer值,如果不存在或转换失败则返回null
     */
    private static Integer getIntegerValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        
        try {
            if (value instanceof Number) {
                return ((Number) value).intValue();
            }
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }
    
    /**
     * 安全获取Long类型的值
     * 
     * @param map 数据Map
     * @param key 键
     * @return Long值,如果不存在或转换失败则返回null
     */
    private static Long getLongValue(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        
        try {
            if (value instanceof Number) {
                return ((Number) value).longValue();
            }
            return Long.parseLong(value.toString());
        } catch (NumberFormatException e) {
            return null;
        }
    }
    
    /**
     * 安全获取Boolean类型的值
     * 
     * @param map 数据Map
     * @param key 键
     * @return Boolean值,如果不存在则返回null
     */
    private static Boolean getBooleanValue(Map<String, Object> map, String key) {
        if (map == null || key == null) {
            return null;
        }
        
        try {
            Object value = map.get(key);
            if (value == null) {
                return null;
            }
            
            if (value instanceof Boolean) {
                return (Boolean) value;
            }
            
            String strValue = value.toString().toLowerCase();
            return "true".equals(strValue) || "1".equals(strValue);
        } catch (Exception e) {
            System.err.println("警告: 获取布尔字段 [" + key + "] 值时异常: " + e.getMessage());
            return null;
        }
    }
}



