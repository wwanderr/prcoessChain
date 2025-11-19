package com.security.processchain.util;

import com.security.processchain.model.RawLog;
import com.security.processchain.service.GraphNode;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * 日志节点拆分工具
 * 
 * 功能：
 * 1. process日志 → 父进程节点 + 子进程节点
 * 2. file/domain/network/registry日志 → 父进程节点 + 子进程节点 + 实体节点
 * 3. 父进程节点的parentProcessGuid通过hash计算
 * 
 * 节点ID规则：
 * - process节点：使用 processGuid
 * - 父进程虚拟节点：使用 parentProcessGuid
 * - file实体节点：processGuid + "_FILE_" + fileMd5 + "_" + targetFilename
 * - domain实体节点：processGuid + "_DOMAIN_" + requestDomain
 * - network实体节点：processGuid + "_NETWORK_" + destAddress
 * - registry实体节点：processGuid + "_REGISTRY_" + hashOf(targetObject)
 */
@Slf4j
public class LogNodeSplitter {
    
    // ========== 已抽取的内部类（现已独立为单独的文件）==========
    // SplitResult.java - 拆分结果
    // EdgePair.java - 边对
    
    /**
     * 拆分日志节点
     * 
     * @param rawLog 原始日志
     * @return 拆分结果
     */
    public static SplitResult splitLogNode(RawLog rawLog) {
        if (rawLog == null) {
            return new SplitResult();
        }
        
        String logType = rawLog.getLogType();
        
        if ("process".equalsIgnoreCase(logType)) {
            // process日志：拆分为父子进程
            return splitProcessLog(rawLog);
            
        } else if (isEntityLogType(logType)) {
            // file/domain/network/registry：拆分为父+子+实体
            return splitEntityLog(rawLog);
            
        } else {
            // 其他类型：不拆分，只创建子节点
            SplitResult result = new SplitResult();
            result.setChildNode(createNodeFromLog(rawLog, rawLog.getProcessGuid()));
            return result;
        }
    }
    
    /**
     * 拆分process日志
     */
    private static SplitResult splitProcessLog(RawLog rawLog) {
        SplitResult result = new SplitResult();
        
        // 1. 创建子进程节点（当前进程）
        String childGuid = rawLog.getProcessGuid();
        GraphNode childNode = createNodeFromLog(rawLog, childGuid);
        childNode.setNodeType("process");
        result.setChildNode(childNode);
        
        // 2. 创建/关联父进程节点
        String parentGuid = rawLog.getParentProcessGuid();
        
        if (parentGuid != null && !parentGuid.isEmpty()) {
            // 创建虚拟父节点（可能会被真实节点合并）
            GraphNode parentNode = createVirtualParentNode(rawLog);
            result.setParentNode(parentNode);
            
            // 创建边：父 → 子
            result.addEdge(parentGuid, childGuid);
            
            log.debug("【节点拆分】process: {} → {}", parentGuid, childGuid);
        }
        
        return result;
    }
    
    /**
     * 拆分实体日志（file/domain/network/registry）
     */
    private static SplitResult splitEntityLog(RawLog rawLog) {
        SplitResult result = new SplitResult();
        
        // 1. 创建子进程节点（发起操作的进程）
        String childGuid = rawLog.getProcessGuid();
        GraphNode childNode = createNodeFromLog(rawLog, childGuid);
        childNode.setNodeType("process");
        result.setChildNode(childNode);
        
        // 2. 创建父进程节点
        String parentGuid = rawLog.getParentProcessGuid();
        if (parentGuid != null && !parentGuid.isEmpty()) {
            GraphNode parentNode = createVirtualParentNode(rawLog);
            result.setParentNode(parentNode);
            
            // 边1：父 → 子
            result.addEdge(parentGuid, childGuid);
        }
        
        // 3. 创建实体节点
        String entityNodeId = generateEntityNodeId(rawLog);
        GraphNode entityNode = createEntityNode(rawLog, entityNodeId);
        result.setEntityNode(entityNode);
        
        // 边2：子 → 实体
        result.addEdge(childGuid, entityNodeId);
        
        log.debug("【节点拆分】{}: {} → {} → {}",
                rawLog.getLogType(), parentGuid, childGuid, entityNodeId);
        
        return result;
    }
    
    /**
     * 创建虚拟父进程节点
     */
    private static GraphNode createVirtualParentNode(RawLog rawLog) {
        GraphNode parentNode = new GraphNode();
        
        // 设置nodeId = log的parentProcessGuid
        parentNode.setNodeId(rawLog.getParentProcessGuid());
        
        // 计算父进程的parentProcessGuid（hash）
        String parentParentGuid = calculateParentProcessGuidHash(rawLog);
        parentNode.setParentProcessGuid(parentParentGuid);
        
        // 标记为虚拟节点
        parentNode.setVirtual(true);
        parentNode.setNodeType("process");
        
        // 提取traceId和hostAddress
        parentNode.setTraceId(rawLog.getTraceId());
        parentNode.setHostAddress(rawLog.getHostAddress());
        
        // 创建虚拟日志（使用parent字段）
        RawLog parentLog = new RawLog();
        parentLog.setProcessGuid(rawLog.getParentProcessGuid());
        parentLog.setParentProcessGuid(parentParentGuid);
        parentLog.setProcessName(rawLog.getParentProcessName());
        parentLog.setImage(rawLog.getParentImage());
        parentLog.setCommandLine(rawLog.getParentCommandLine());
        parentLog.setProcessUserName(rawLog.getParentProcessUserName());
        parentLog.setProcessId(rawLog.getParentProcessId());
        parentLog.setLogType("process");
        parentLog.setTraceId(rawLog.getTraceId());
        parentLog.setHostAddress(rawLog.getHostAddress());
        parentLog.setStartTime(rawLog.getStartTime());
        
        parentNode.addLog(parentLog);
        
        return parentNode;
    }
    
    /**
     * 从日志创建节点
     */
    private static GraphNode createNodeFromLog(RawLog rawLog, String nodeId) {
        GraphNode node = new GraphNode();
        
        node.setNodeId(nodeId);
        node.setParentProcessGuid(rawLog.getParentProcessGuid());
        node.setTraceId(rawLog.getTraceId());
        node.setHostAddress(rawLog.getHostAddress());
        node.setNodeType(rawLog.getLogType());
        
        node.addLog(rawLog);
        
        return node;
    }
    
    /**
     * 创建实体节点
     */
    private static GraphNode createEntityNode(RawLog rawLog, String entityNodeId) {
        GraphNode node = new GraphNode();
        
        node.setNodeId(entityNodeId);
        node.setTraceId(rawLog.getTraceId());
        node.setHostAddress(rawLog.getHostAddress());
        node.setNodeType(rawLog.getLogType() + "_entity");
        
        // 实体节点没有parentProcessGuid
        node.setParentProcessGuid(null);
        
        node.addLog(rawLog);
        
        return node;
    }
    
    /**
     * 计算父进程的parentProcessGuid（hash）
     * 
     * 使用字段：parentProcessName + parentProcessUserName + parentImage + parentCommandLine
     */
    private static String calculateParentProcessGuidHash(RawLog rawLog) {
        StringBuilder sb = new StringBuilder();
        
        if (rawLog.getParentProcessName() != null) {
            sb.append(rawLog.getParentProcessName());
        }
        if (rawLog.getParentProcessUserName() != null) {
            sb.append(rawLog.getParentProcessUserName());
        }
        if (rawLog.getParentImage() != null) {
            sb.append(rawLog.getParentImage());
        }
        if (rawLog.getParentCommandLine() != null) {
            sb.append(rawLog.getParentCommandLine());
        }
        
        // 如果所有字段都为空，返回特殊标记
        if (sb.length() == 0) {
            return "VIRTUAL_PARENT_" + rawLog.getParentProcessGuid();
        }
        
        // 计算MD5 hash
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(sb.toString().getBytes(StandardCharsets.UTF_8));
            return "HASH_" + bytesToHex(hash);
        } catch (Exception e) {
            // 降级：使用简单标记
            return "HASH_" + Math.abs(sb.toString().hashCode());
        }
    }
    
    /**
     * 生成实体节点ID
     */
    private static String generateEntityNodeId(RawLog rawLog) {
        String logType = rawLog.getLogType().toLowerCase();
        String baseId = rawLog.getProcessGuid();
        
        switch (logType) {
            case "file":
                // file节点ID = processGuid + "_FILE_" + fileMd5 + "_" + targetFilename
                String fileMd5 = rawLog.getFileMd5() != null ? rawLog.getFileMd5() : "NOMD5";
                String filename = rawLog.getTargetFilename() != null ? 
                    sanitizeForId(rawLog.getTargetFilename()) : "NONAME";
                return baseId + "_FILE_" + fileMd5 + "_" + filename;
                
            case "domain":
                // domain节点ID = processGuid + "_DOMAIN_" + requestDomain
                String domain = rawLog.getRequestDomain() != null ? 
                    sanitizeForId(rawLog.getRequestDomain()) : "NODOMAIN";
                return baseId + "_DOMAIN_" + domain;
                
            case "network":
                // network节点ID = processGuid + "_NETWORK_" + destAddress
                String destAddr = rawLog.getDestAddress() != null ? 
                    sanitizeForId(rawLog.getDestAddress()) : "NOADDR";
                String destPort = rawLog.getDestPort() != null ? rawLog.getDestPort() : "";
                return baseId + "_NETWORK_" + destAddr + "_" + destPort;
                
            case "registry":
                // registry节点ID = processGuid + "_REGISTRY_" + hashOf(targetObject)
                String targetObj = rawLog.getTargetObject() != null ? rawLog.getTargetObject() : "NOOBJ";
                String objHash = String.valueOf(Math.abs(targetObj.hashCode()));
                return baseId + "_REGISTRY_" + objHash;
                
            default:
                return baseId + "_ENTITY_" + Math.abs(logType.hashCode());
        }
    }
    
    /**
     * 清理字符串用于ID（移除特殊字符）
     */
    private static String sanitizeForId(String str) {
        if (str == null) {
            return "";
        }
        // 只保留字母、数字、点、下划线、短横线
        return str.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
    
    /**
     * 判断是否是实体类型日志
     */
    private static boolean isEntityLogType(String logType) {
        if (logType == null) {
            return false;
        }
        String lower = logType.toLowerCase();
        return "file".equals(lower) ||
               "domain".equals(lower) ||
               "network".equals(lower) ||
               "registry".equals(lower);
    }
    
    /**
     * 字节数组转十六进制字符串
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

