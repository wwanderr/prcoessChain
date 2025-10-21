package com.security.processchain.service;

import com.security.processchain.model.ProcessEdge;
import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;

/**
 * 事件进程链转换器
 * 提供从 Builder 内部节点/边到最终返回模型的转换逻辑
 * 将转换逻辑从 Service 层解耦，便于维护和测试
 */
@Slf4j
public final class IncidentConverters {

    private IncidentConverters() {}

    /**
     * 默认节点映射器实现
     */
    public static final NodeMapper NODE_MAPPER = builderNode -> {
        ProcessNode finalNode = new ProcessNode();
        finalNode.setNodeId(builderNode.getProcessGuid());
        finalNode.setIsChainNode(true);

        ChainNode chainNode = new ChainNode();

        List<RawAlarm> alarms = builderNode.getAlarms();
        List<RawLog> logs = builderNode.getLogs();

        boolean isAlarm = alarms != null && !alarms.isEmpty();
        chainNode.setIsAlarm(isAlarm);

        boolean isRoot = builderNode.getParentProcessGuid() == null || 
                        builderNode.getParentProcessGuid().trim().isEmpty();
        chainNode.setIsRoot(isRoot);
        chainNode.setIsBroken(false);

        if (isAlarm) {
            RawAlarm latestAlarm = getLatestAlarm(alarms);
            if (latestAlarm != null) {
                AlarmNodeInfo alarmInfo = convertToAlarmNodeInfo(latestAlarm);
                chainNode.setAlarmNodeInfo(alarmInfo);
                finalNode.setNodeThreatSeverity(mapToThreatSeverity(latestAlarm.getThreatSeverity()));
            }
        }

        if (logs != null && !logs.isEmpty()) {
            RawLog latestLog = getLatestLog(logs);
            if (latestLog != null && latestLog.getLogType() != null) {
                finalNode.setLogType(mapToNodeType(latestLog.getLogType()));
                chainNode.setProcessEntity(convertToProcessEntity(latestLog));
                chainNode.setEntity(convertToEntity(latestLog, latestLog.getLogType()));
            }
        } else if (isAlarm && alarms != null && !alarms.isEmpty()) {
            RawAlarm firstAlarm = alarms.get(0);
            if (firstAlarm != null && firstAlarm.getLogType() != null) {
                finalNode.setLogType(mapToNodeType(firstAlarm.getLogType()));
            }
        }

        finalNode.setChainNode(chainNode);
        finalNode.setStoryNode(null);
        return finalNode;
    };

    /**
     * 默认边映射器实现
     */
    public static final EdgeMapper EDGE_MAPPER = builderEdge -> {
        ProcessEdge finalEdge = new ProcessEdge();
        finalEdge.setSource(builderEdge.getSource());
        finalEdge.setTarget(builderEdge.getTarget());
        finalEdge.setVal(builderEdge.getVal());
        return finalEdge;
    };

    /**
     * 选择时间最近的告警
     */
    private static RawAlarm getLatestAlarm(List<RawAlarm> alarms) {
        if (alarms == null || alarms.isEmpty()) {
            return null;
        }
        RawAlarm latest = null;
        for (RawAlarm alarm : alarms) {
            if (alarm == null) continue;
            if (latest == null) {
                latest = alarm;
                continue;
            }
            String a = alarm.getStartTime();
            String b = latest.getStartTime();
            if (a != null && (b == null || a.compareTo(b) > 0)) {
                latest = alarm;
            }
        }
        return latest;
    }

    /**
     * 选择时间最近的日志
     */
    private static RawLog getLatestLog(List<RawLog> logs) {
        if (logs == null || logs.isEmpty()) {
            return null;
        }
        RawLog latest = null;
        for (RawLog logItem : logs) {
            if (logItem == null) continue;
            if (latest == null) {
                latest = logItem;
                continue;
            }
            String a = logItem.getStartTime();
            String b = latest.getStartTime();
            if (a != null && (b == null || a.compareTo(b) > 0)) {
                latest = logItem;
            }
        }
        return latest;
    }

    /**
     * 将原始告警转换为AlarmNodeInfo
     */
    private static AlarmNodeInfo convertToAlarmNodeInfo(RawAlarm alarm) {
        if (alarm == null) return null;

        AlarmNodeInfo alarmInfo = new AlarmNodeInfo();
        alarmInfo.setAlarmName(alarm.getAlarmName());
        alarmInfo.setThreatSeverity(mapToThreatSeverity(alarm.getThreatSeverity()));

        if (alarm.getOtherFields() != null) {
            Map<String, Object> fields = alarm.getOtherFields();
            alarmInfo.setDvcAction(getStringFromMap(fields, "dvcAction"));
            alarmInfo.setAlarmDescription(getStringFromMap(fields, "alarmDescription"));
            alarmInfo.setAlarmSource(getStringFromMap(fields, "alarmSource"));
            alarmInfo.setAlarmResults(getStringFromMap(fields, "alarmResults"));
        }

        return alarmInfo;
    }

    /**
     * 将原始日志转换为ProcessEntity
     * 非null条件：eventType = processCreate 且 logType = process
     */
    private static ProcessEntity convertToProcessEntity(RawLog log) {
        if (log == null) return null;
        
        // 检查非null条件
        if (!"process".equalsIgnoreCase(log.getLogType())) return null;
        if (!"processCreate".equalsIgnoreCase(log.getEventType())) return null;
        
        if (log.getProcessName() == null && log.getImage() == null) return null;

        ProcessEntity entity = new ProcessEntity();
        entity.setOpType(log.getOpType());
        entity.setLocaltime(log.getStartTime());
        entity.setProcessId(log.getProcessId());
        entity.setImage(log.getImage());
        entity.setCommandline(log.getCommandLine());
        entity.setProcessUserName(log.getProcessUserName());
        entity.setProcessName(log.getProcessName());

        return entity;
    }

    /**
     * 根据logType将原始日志转换为对应的实体
     */
    private static Object convertToEntity(RawLog log, String logType) {
        if (log == null || logType == null) return null;

        String type = logType.toLowerCase();
        switch (type) {
            case "file":
                return convertToFileEntity(log);
            case "network":
                return convertToNetworkEntity(log);
            case "domain":
                return convertToDomainEntity(log);
            case "registry":
                return convertToRegistryEntity(log);
            case "process":
                return null;
            default:
                return null;
        }
    }

    /**
     * 转换为FileEntity
     * 非null条件：logType = file 且 opType 为 create/write/delete
     */
    private static FileEntity convertToFileEntity(RawLog log) {
        if (log == null) return null;
        
        // 检查非null条件
        if (!"file".equalsIgnoreCase(log.getLogType())) return null;
        
        String opType = log.getOpType();
        if (opType == null) return null;
        opType = opType.toLowerCase();
        if (!"create".equals(opType) && !"write".equals(opType) && !"delete".equals(opType)) {
            return null;
        }
        
        FileEntity entity = new FileEntity();
        entity.setFilePath(log.getFilePath());
        entity.setTargetFilename(log.getTargetFilename());
        entity.setFileName(log.getFileName());
        entity.setFileMd5(log.getFileMd5());
        entity.setFileType(log.getFileType());

        try {
            if (log.getFileSize() != null) {
                entity.setFileSize(Long.parseLong(log.getFileSize()));
            }
        } catch (NumberFormatException e) {
            // 忽略格式错误
        }

        return entity;
    }

    /**
     * 转换为NetworkEntity
     * 非null条件：logType = network 且 opType = connect
     */
    private static NetworkEntity convertToNetworkEntity(RawLog log) {
        if (log == null) return null;
        
        // 检查非null条件
        if (!"network".equalsIgnoreCase(log.getLogType())) return null;
        if (!"connect".equalsIgnoreCase(log.getOpType())) return null;
        
        NetworkEntity entity = new NetworkEntity();
        entity.setTransProtocol(log.getTransProtocol());
        entity.setSrcAddress(log.getSrcAddress());
        entity.setDestAddress(log.getDestAddress());

        try {
            if (log.getSrcPort() != null) {
                entity.setSrcPort(Integer.parseInt(log.getSrcPort()));
            }
            if (log.getDestPort() != null) {
                entity.setDestPort(Integer.parseInt(log.getDestPort()));
            }
        } catch (NumberFormatException e) {
            // 忽略格式错误
        }

        if (log.getInitiated() != null) {
            entity.setInitiated(Boolean.parseBoolean(log.getInitiated()));
        }

        return entity;
    }

    /**
     * 转换为DomainEntity
     * 非null条件：logType = domain 且 opType = connect
     */
    private static DomainEntity convertToDomainEntity(RawLog log) {
        if (log == null) return null;
        
        // 检查非null条件
        if (!"domain".equalsIgnoreCase(log.getLogType())) return null;
        if (!"connect".equalsIgnoreCase(log.getOpType())) return null;
        
        DomainEntity entity = new DomainEntity();
        entity.setRequestDomain(log.getRequestDomain());
        entity.setQueryResults(log.getQueryResults());
        return entity;
    }

    /**
     * 转换为RegistryEntity
     * 非null条件：logType = registry 且 opType = setValue
     */
    private static RegistryEntity convertToRegistryEntity(RawLog log) {
        if (log == null) return null;
        
        // 检查非null条件
        if (!"registry".equalsIgnoreCase(log.getLogType())) return null;
        if (!"setValue".equalsIgnoreCase(log.getOpType())) return null;
        
        RegistryEntity entity = new RegistryEntity();
        entity.setTargetObject(log.getTargetObject());
        entity.setRegValue(log.getRegValue());
        return entity;
    }

    /**
     * 从Map中安全获取String值
     */
    private static String getStringFromMap(Map<String, Object> map, String key) {
        if (map == null || key == null) return null;
        Object value = map.get(key);
        return value != null ? value.toString() : null;
    }

    /**
     * 将字符串logType映射为NodeType枚举
     */
    public static NodeType mapToNodeType(String logType) {
        if (logType == null) return NodeType.UNKNOWN;
        String t = logType.trim().toLowerCase();
        switch (t) {
            case "process":
                return NodeType.PROCESS;
            case "file":
                return NodeType.FILE;
            case "network":
                return NodeType.NETWORK;
            case "domain":
                return NodeType.DOMAIN;
            case "registry":
                return NodeType.REGISTRY;
            default:
                return NodeType.UNKNOWN;
        }
    }

    /**
     * 将字符串威胁等级映射为ThreatSeverity枚举（支持中文/英文）
     */
    public static ThreatSeverity mapToThreatSeverity(String severity) {
        if (severity == null) return ThreatSeverity.UNKNOWN;
        String s = severity.trim();
        if ("高".equals(s) || "HIGH".equalsIgnoreCase(s)) return ThreatSeverity.HIGH;
        if ("中".equals(s) || "MEDIUM".equalsIgnoreCase(s)) return ThreatSeverity.MEDIUM;
        if ("低".equals(s) || "LOW".equalsIgnoreCase(s)) return ThreatSeverity.LOW;
        return ThreatSeverity.UNKNOWN;
    }
}



