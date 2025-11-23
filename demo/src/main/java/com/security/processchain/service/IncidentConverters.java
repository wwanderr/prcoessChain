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

        // createNodeFromLog这块附近
        List<RawAlarm> alarms = builderNode.getAlarms();
        // existingNode.addLog(entityLog);这块流转
        List<RawLog> logs = builderNode.getLogs();

        boolean isAlarm = alarms != null && !alarms.isEmpty();
        chainNode.setIsAlarm(isAlarm);

        boolean isRoot = builderNode.getParentProcessGuid() == null || 
                        builderNode.getParentProcessGuid().trim().isEmpty();
        chainNode.setIsRoot(isRoot);
        chainNode.setIsBroken(false);

        // ========== 关键修改：根据 nodeType 填充实体字段 ==========
        String nodeType = builderNode.getNodeType();
        
        if (logs != null && !logs.isEmpty()) {
            RawLog latestLog = getLatestLog(logs);
            if (latestLog != null) {
                // 根据 nodeType 决定如何填充实体
                if ("process".equals(nodeType)) {
                    // ========== 进程节点：设置告警信息和进程实体 ==========
                    finalNode.setLogType("process");
                    finalNode.setOpType(latestLog.getOpType());
                    
                    // 进程节点才设置告警信息
                    if (isAlarm) {
                        RawAlarm latestAlarm = getLatestAlarm(alarms);
                        if (latestAlarm != null) {
                            AlarmNodeInfo alarmInfo = convertToAlarmNodeInfo(latestAlarm);
                            chainNode.setAlarmNodeInfo(alarmInfo);
                            finalNode.setNodeThreatSeverity(mapToThreatSeverity(latestAlarm.getThreatSeverity()));
                        }
                    }
                    
                    // ✅ 判断是否是虚拟父节点
                    boolean isVirtualParent = builderNode.getParentProcessGuid() == null && builderNode.getIsVirtual();
                    
                    // 只设置 processEntity，entity 为 null
                    chainNode.setProcessEntity(convertToProcessEntityForProcessNode(latestLog, isVirtualParent));
                    chainNode.setEntity(null);
                    
                } else if (nodeType != null && nodeType.endsWith("_entity")) {
                    // ========== 实体节点：只设置实体信息，不设置告警和进程实体 ==========
                    String entityType = nodeType.replace("_entity", "");
                    finalNode.setLogType(entityType);  // "file", "domain", "network", "registry"
                    finalNode.setOpType(latestLog.getOpType());
                    
                    // 实体节点不设置告警信息
                    chainNode.setAlarmNodeInfo(null);
                    
                    // 只设置 entity，processEntity 为 null
                    chainNode.setProcessEntity(null);
                    chainNode.setEntity(convertToEntity(latestLog, entityType));
                    
                } else {
                    // 兜底逻辑（保持原有逻辑）
                    finalNode.setLogType(latestLog.getLogType());
                    finalNode.setOpType(latestLog.getOpType());
                    
                    // 兜底逻辑也可能有告警
                    if (isAlarm) {
                        RawAlarm latestAlarm = getLatestAlarm(alarms);
                        if (latestAlarm != null) {
                            AlarmNodeInfo alarmInfo = convertToAlarmNodeInfo(latestAlarm);
                            chainNode.setAlarmNodeInfo(alarmInfo);
                            finalNode.setNodeThreatSeverity(mapToThreatSeverity(latestAlarm.getThreatSeverity()));
                        }
                    }
                    
                    Object entity = convertToEntity(latestLog, latestLog.getLogType());
                    chainNode.setEntity(entity);
                    chainNode.setProcessEntity(convertToProcessEntity(latestLog, entity));
                }
            }
        } else if (isAlarm && alarms != null && !alarms.isEmpty()) {
            // ========== 只有告警没有日志的情况 ==========
            RawAlarm firstAlarm = alarms.get(0);
            if (firstAlarm != null && firstAlarm.getLogType() != null) {
                String logType = firstAlarm.getLogType();

                // 设置基本信息
                finalNode.setLogType(logType);
                finalNode.setOpType(firstAlarm.getOpType());
                
                // 根据 nodeType 决定如何填充实体
                if ("process".equals(nodeType)) {
                    // ========== 进程节点：设置告警信息和进程实体 ==========
                    AlarmNodeInfo alarmInfo = convertToAlarmNodeInfo(firstAlarm);
                    chainNode.setAlarmNodeInfo(alarmInfo);
                    finalNode.setNodeThreatSeverity(mapToThreatSeverity(firstAlarm.getThreatSeverity()));
                    
                    // ✅ 判断是否是虚拟父节点
                    boolean isVirtualParent = builderNode.getParentProcessGuid() == null && builderNode.getIsVirtual();
                    
                    // ✅ 从告警中抽取 ProcessEntity
                    chainNode.setProcessEntity(convertToProcessEntityFromAlarm(firstAlarm, isVirtualParent));
                    chainNode.setEntity(null);
                    
                } else if (nodeType != null && nodeType.endsWith("_entity")) {
                    // ========== 实体节点：只设置实体信息 ==========
                    String entityType = nodeType.replace("_entity", "");
                    
                    // 实体节点不设置告警信息
                    chainNode.setAlarmNodeInfo(null);
                    
                    // ✅ 从告警中抽取对应的实体
                    chainNode.setProcessEntity(null);
                    chainNode.setEntity(convertToEntityFromAlarm(firstAlarm, entityType));
                    
                } else {
                    // 兜底逻辑：设置告警信息
                    AlarmNodeInfo alarmInfo = convertToAlarmNodeInfo(firstAlarm);
                    chainNode.setAlarmNodeInfo(alarmInfo);
                    finalNode.setNodeThreatSeverity(mapToThreatSeverity(firstAlarm.getThreatSeverity()));
                }
            }
        }

        finalNode.setChainNode(chainNode);
        finalNode.setStoryNode(null);
        return finalNode;
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
     * 优先选择非虚拟日志，避免虚拟父节点的日志（opType=create）覆盖真实日志
     */
    private static RawLog getLatestLog(List<RawLog> logs) {
        if (logs == null || logs.isEmpty()) {
            return null;
        }
        
        // 第一步：区分虚拟日志和真实日志
        RawLog latestRealLog = null;
        RawLog latestVirtualLog = null;
        
        for (RawLog logItem : logs) {
            if (logItem == null) continue;
            
            if (isVirtualLog(logItem)) {
                // 虚拟日志
                if (latestVirtualLog == null) {
                    latestVirtualLog = logItem;
                } else {
                    String a = logItem.getStartTime();
                    String b = latestVirtualLog.getStartTime();
                    if (a != null && (b == null || a.compareTo(b) > 0)) {
                        latestVirtualLog = logItem;
                    }
                }
            } else {
                // 真实日志
                if (latestRealLog == null) {
                    latestRealLog = logItem;
                } else {
                    String a = logItem.getStartTime();
                    String b = latestRealLog.getStartTime();
                    if (a != null && (b == null || a.compareTo(b) > 0)) {
                        latestRealLog = logItem;
                    }
                }
            }
        }
        
        // 第二步：优先返回真实日志，没有真实日志才返回虚拟日志
        return latestRealLog != null ? latestRealLog : latestVirtualLog;
    }
    
    /**
     * 判断是否为虚拟日志
     * 虚拟日志是在节点拆分时为虚拟父节点创建的日志
     */
    private static boolean isVirtualLog(RawLog rawLog) {
        if (rawLog == null) return false;
        
        String eventId = rawLog.getEventId();
        // 虚拟日志的 eventId 以 "VIRTUAL_LOG_" 开头
        return eventId != null && eventId.startsWith("VIRTUAL_LOG_");
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
            
            // 映射 alarmResults: OK→成功、FAIL→失败、UNKNOWN→尝试
            String rawResults = getStringFromMap(fields, "alarmResults");
            alarmInfo.setAlarmResults(mapAlarmResults(rawResults));
        }

        return alarmInfo;
    }
    
    /**
     * 映射 alarmResults 为中文
     * OK → 成功
     * FAIL → 失败
     * UNKNOWN → 尝试
     */
    private static String mapAlarmResults(String results) {
        if (results == null) return "";
        String upper = results.trim().toUpperCase();
        switch (upper) {
            case "OK":
                return "成功";
            case "FAIL":
                return "失败";
            case "UNKNOWN":
                return "尝试";
            default:
                return results;  // 保持原值
        }
    }
    
    /**
     * 映射文件类型为中文
     */
    private static String mapFileType(String fileType) {
        if (fileType == null) return "";
        String lower = fileType.trim().toLowerCase();
        switch (lower) {
            case "pe":
                return "可移植可执行文件";
            case "elf":
                return "可执行与可链接格式";
            case "macho":
                return "Mach 对象文件";
            case "script":
                return "脚本文件";
            case "document":
                return "文档文件";
            case "archive":
                return "压缩/归档文件";
            case "image":
                return "图像文件";
            case "text":
                return "文本文件";
            case "lnk":
                return "快捷方式文件";
            case "html":
                return "超文本标记语言文件";
            case "disk-image":
                return "磁盘映像文件";
            case "jar":
                return "Java 归档文件";
            case "firmware":
                return "固件文件";
            case "virtual":
                return "虚拟文件";
            case "corrupted":
                return "损坏文件";
            case "unknown":
                return "未知文件类型";
            default:
                return fileType;  // 保持原值
        }
    }
    
    /**
     * 将字节转换为 MB 格式
     * 例如：19969668 → "19.97MB"
     */
    private static String formatFileSize(Long bytes) {
        if (bytes == null) return "";
        double mb = bytes / (1024.0 * 1024.0);
        return String.format("%.2fMB", mb);
    }

    /**
     * 专门用于进程节点的 ProcessEntity 转换（包括虚拟父节点）
     * 
     * 这个方法用于新的建图方案中，对已经拆分好的进程节点进行转换
     * 不再检查 eventType 或 logType，只要有进程信息就转换
     * 
     * @param log 原始日志（可能是真实日志，也可能是虚拟父节点的日志）
     * @param isVirtualParent 是否是虚拟父节点（true：从 parent 字段提取；false：从 process 字段提取）
     * @return ProcessEntity，如果没有进程信息返回null
     */
    private static ProcessEntity convertToProcessEntityForProcessNode(RawLog log, boolean isVirtualParent) {
        if (log == null) return null;
        
        // 构建 ProcessEntity
        ProcessEntity processEntity = new ProcessEntity();
        
        if (isVirtualParent) {
            // ========== 虚拟父节点：从日志的 parent 字段中提取 ==========
            processEntity.setOpType(log.getOpType());
            processEntity.setLocaltime(log.getStartTime());
            processEntity.setProcessId(log.getParentProcessId() != null ? String.valueOf(log.getParentProcessId()) : null);
            processEntity.setProcessGuid(log.getParentProcessGuid());  // 虚拟父节点的 processGuid 就是 parentProcessGuid
            processEntity.setParentProcessGuid(null);  // 虚拟父节点的 parentProcessGuid 永远是 null
            processEntity.setImage(log.getParentImage());
            processEntity.setCommandline(log.getParentCommandLine());
            processEntity.setProcessUserName(log.getParentProcessUserName());
            
            // 处理 processName：从 parentProcessName 获取
            String processName = log.getParentProcessName();
            if (processName == null || processName.trim().isEmpty()) {
                processName = "进程.exe";
            }
            processEntity.setProcessName(processName);
        } else {
            // ========== 真实节点：从日志的 process 字段中提取 ==========
            processEntity.setOpType(log.getOpType());
            processEntity.setLocaltime(log.getStartTime());
            processEntity.setProcessId(log.getProcessId() != null ? String.valueOf(log.getProcessId()) : null);
            processEntity.setProcessGuid(log.getProcessGuid());
            processEntity.setParentProcessGuid(log.getParentProcessGuid());
            processEntity.setImage(log.getImage());
            processEntity.setCommandline(log.getCommandLine());
            processEntity.setProcessUserName(log.getProcessUserName());
            
            // 处理 processName：从 processName 获取
            String processName = log.getProcessName();
            if (processName == null || processName.trim().isEmpty()) {
                processName = "进程.exe";
            }
            processEntity.setProcessName(processName);
        }

        return processEntity;
    }
    
    /**
     * 从告警转换为 ProcessEntity（用于只有告警没有日志的情况）
     * 
     * @param alarm 原始告警
     * @param isVirtualParent 是否是虚拟父节点（true：从 parent 字段提取；false：从 process 字段提取）
     * @return ProcessEntity，如果告警中没有进程信息返回null
     */
    private static ProcessEntity convertToProcessEntityFromAlarm(RawAlarm alarm, boolean isVirtualParent) {
        if (alarm == null) return null;
        
        // 构建 ProcessEntity
        ProcessEntity processEntity = new ProcessEntity();
        
        if (isVirtualParent) {
            // ========== 虚拟父节点：从告警的 parent 字段中提取 ==========
            processEntity.setOpType(alarm.getOpType());
            processEntity.setLocaltime(alarm.getStartTime());
            processEntity.setProcessId(alarm.getParentProcessId() != null ? String.valueOf(alarm.getParentProcessId()) : null);
            processEntity.setProcessGuid(alarm.getParentProcessGuid());  // 虚拟父节点的 processGuid 就是 parentProcessGuid
            processEntity.setParentProcessGuid(null);  // 虚拟父节点的 parentProcessGuid 永远是 null
            processEntity.setImage(alarm.getParentImage());
            processEntity.setCommandline(alarm.getParentCommandLine());
            processEntity.setProcessUserName(alarm.getParentProcessUserName());
            
            // 处理 processName：从 parentProcessName 获取
            String processName = alarm.getParentProcessName();
            if (processName == null || processName.trim().isEmpty()) {
                processName = "进程.exe";
            }
            processEntity.setProcessName(processName);
        } else {
            // ========== 真实节点：从告警的 process 字段中提取 ==========
            processEntity.setOpType(alarm.getOpType());
            processEntity.setLocaltime(alarm.getStartTime());
            processEntity.setProcessId(alarm.getProcessId() != null ? String.valueOf(alarm.getProcessId()) : null);
            processEntity.setProcessGuid(alarm.getProcessGuid());
            processEntity.setParentProcessGuid(alarm.getParentProcessGuid());
            processEntity.setImage(alarm.getImage());
            processEntity.setCommandline(alarm.getCommandLine());
            processEntity.setProcessUserName(alarm.getProcessUserName());
            
            // 处理 processName：从 processName 获取
            String processName = alarm.getProcessName();
            if (processName == null || processName.trim().isEmpty()) {
                processName = "进程.exe";
            }
            processEntity.setProcessName(processName);
        }
        
        return processEntity;
    }
    
    /**
     * 将原始日志转换为ProcessEntity（旧方法，保留用于兼容）
     * 
     * 非null条件：
     * 1. 进程节点：eventType = processCreate 且 logType = process
     * 2. 其他节点（文件/外联/域名/注册表）：如果对应的实体能构建（entity != null），则也构建 ProcessEntity
     *    因为这些操作都是由进程发起的
     * 
     * @param log 原始日志
     * @param entity 对应类型的实体（FileEntity/NetworkEntity/DomainEntity/RegistryEntity）
     * @return ProcessEntity，如果不满足条件返回null
     */
    private static ProcessEntity convertToProcessEntity(RawLog log, Object entity) {
        if (log == null) return null;
        
        // 必须至少有进程名或镜像路径
        if (log.getProcessName() == null && log.getImage() == null) return null;
        
        // 情况1: logType = process，需要检查 eventType = processCreate
        if ("process".equalsIgnoreCase(log.getLogType())) {
            if (!"processCreate".equalsIgnoreCase(log.getEventType())) {
                return null;  // 进程节点必须是 processCreate
            }
        } 
        // 情况2: 其他类型节点（文件/外联/域名/注册表）
        // 只有当对应的实体能构建时（entity != null），才构建 ProcessEntity
        else {
            if (entity == null) {
                return null;  // 如果对应实体构建失败，则不构建 ProcessEntity
            }
        }
        
        // 构建 ProcessEntity
        ProcessEntity processEntity = new ProcessEntity();
        processEntity.setOpType(log.getOpType());
        processEntity.setLocaltime(log.getStartTime());
        processEntity.setProcessId(log.getProcessId() != null ? String.valueOf(log.getProcessId()) : null);
        processEntity.setImage(log.getImage());
        processEntity.setCommandline(log.getCommandLine());
        processEntity.setProcessUserName(log.getProcessUserName());
        
        // 处理 processName：
        // - logType=process 时，为空则显示 "进程.exe"
        // - logType=file 时，为空则保持空
        String processName = log.getProcessName();
        if ((processName == null || processName.trim().isEmpty()) && 
            "process".equalsIgnoreCase(log.getLogType())) {
            processName = "进程.exe";
        }
        processEntity.setProcessName(processName);

        return processEntity;
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
     * 从告警中根据logType将原始告警转换为对应的实体
     */
    private static Object convertToEntityFromAlarm(RawAlarm alarm, String logType) {
        if (alarm == null || logType == null) return null;

        String type = logType.toLowerCase();
        switch (type) {
            case "file":
                return convertToFileEntityFromAlarm(alarm);
            case "network":
                return convertToNetworkEntityFromAlarm(alarm);
            case "domain":
                return convertToDomainEntityFromAlarm(alarm);
            case "registry":
                return convertToRegistryEntityFromAlarm(alarm);
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
        
        // 映射文件类型为中文
        entity.setFileType(mapFileType(log.getFileType()));

        // 转换文件大小为 MB 格式
        try {
            if (log.getFileSize() != null && !log.getFileSize().trim().isEmpty()) {
                Long bytes = Long.parseLong(log.getFileSize());
                entity.setFileSize(formatFileSize(bytes));
            }
        } catch (NumberFormatException e) {
            // 忽略格式错误，保持空字符串
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
        
        // 提取 targetObject 路径的最后一层
        String targetObject = log.getTargetObject();
        if (targetObject != null && !targetObject.trim().isEmpty()) {
            entity.setTargetObjectName(extractLastPathSegment(targetObject));
        }
        
        return entity;
    }
    
    /**
     * 提取路径的最后一层
     * 例如："HKU\\S-1-5-21...\\Toolbar\\Locked" → "Locked"
     */
    private static String extractLastPathSegment(String path) {
        if (path == null || path.trim().isEmpty()) {
            return "";
        }
        
        // 移除末尾的反斜杠（如果有）
        String trimmed = path.trim();
        if (trimmed.endsWith("\\")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        
        // 查找最后一个反斜杠的位置
        int lastBackslash = trimmed.lastIndexOf('\\');
        if (lastBackslash >= 0 && lastBackslash < trimmed.length() - 1) {
            return trimmed.substring(lastBackslash + 1);
        }
        
        // 如果没有反斜杠，返回整个字符串
        return trimmed;
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
     * @deprecated 不再使用枚举类型，直接使用String类型的logType以支持更多类型
     */
    @Deprecated
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
    
    // ========== 从告警中抽取实体的方法 ==========
    
    /**
     * 从告警转换为FileEntity
     */
    private static FileEntity convertToFileEntityFromAlarm(RawAlarm alarm) {
        if (alarm == null) return null;
        
        FileEntity entity = new FileEntity();
        entity.setTargetFilename(alarm.getTargetFilename());
        entity.setFileName(alarm.getFileName());
        entity.setFileMd5(alarm.getFileMd5());
        
        // 注意：告警数据中可能缺少一些字段（如 filePath, fileSize, fileType）
        // 这些字段保持为 null
        
        return entity;
    }
    
    /**
     * 从告警转换为NetworkEntity
     */
    private static NetworkEntity convertToNetworkEntityFromAlarm(RawAlarm alarm) {
        if (alarm == null) return null;
        
        NetworkEntity entity = new NetworkEntity();
        entity.setSrcAddress(alarm.getSrcAddress());
        entity.setDestAddress(alarm.getDestAddress());
        
        try {
            if (alarm.getSrcPort() != null) {
                entity.setSrcPort(Integer.parseInt(alarm.getSrcPort()));
            }
            if (alarm.getDestPort() != null) {
                entity.setDestPort(Integer.parseInt(alarm.getDestPort()));
            }
        } catch (NumberFormatException e) {
            // 忽略格式错误
        }
        
        // 注意：告警数据中可能缺少 transProtocol、initiated 字段
        
        return entity;
    }
    
    /**
     * 从告警转换为DomainEntity
     */
    private static DomainEntity convertToDomainEntityFromAlarm(RawAlarm alarm) {
        if (alarm == null) return null;
        
        DomainEntity entity = new DomainEntity();
        entity.setRequestDomain(alarm.getRequestDomain());
        
        // 注意：告警数据中可能缺少 queryResults 字段
        
        return entity;
    }
    
    /**
     * 从告警转换为RegistryEntity
     */
    private static RegistryEntity convertToRegistryEntityFromAlarm(RawAlarm alarm) {
        if (alarm == null) return null;
        
        RegistryEntity entity = new RegistryEntity();
        entity.setTargetObject(alarm.getTargetObject());
        entity.setRegValue(alarm.getRegValue());
        
        // 提取 targetObject 路径的最后一层
        String targetObject = alarm.getTargetObject();
        if (targetObject != null && !targetObject.trim().isEmpty()) {
            entity.setTargetObjectName(extractLastPathSegment(targetObject));
        }
        
        return entity;
    }
}



