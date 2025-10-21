package com.security.processchain.service.impl;

import com.security.processchain.constants.ProcessChainConstants;
import com.security.processchain.model.IpMappingRelation;
import com.security.processchain.model.ProcessEdge;
import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.*;
import com.security.processchain.util.AlarmElectionUtil;
import com.security.processchain.util.Pair;
import com.security.processchain.util.TimeUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * 进程链服务实现类（SpringBoot版本）
 * 使用OptimizedESQueryService进行批量查询优化
 */
@Slf4j
@Service
public class ProcessChainServiceImpl {

    @Autowired
    private OptimizedESQueryService esQueryService;

    /**
     * 为多个IP生成进程链（批量优化版本）
     * 所有IP的进程链合并到一个IncidentProcessChain中
     * 支持合并网侧和端侧进程链
     * 
     * @param ipMappingRelation IP映射关系数据结构
     * @param networkChain 网侧进程链（节点和边），可以为null
     * @return 合并后的进程链
     */
    public IncidentProcessChain generateProcessChains(
            IpMappingRelation ipMappingRelation,
            Pair<List<ProcessNode>, List<ProcessEdge>> networkChain) {
        if (ipMappingRelation == null || ipMappingRelation.getIpAndAssociation() == null 
                || ipMappingRelation.getIpAndAssociation().isEmpty()) {
            log.error("【进程链生成】-> 错误: IP映射关系为空");
            return null;
        }

        List<String> ips = ipMappingRelation.getAllIps();
        
        // 收集所有告警和日志
        List<RawAlarm> allSelectedAlarms = new ArrayList<>();
        List<RawLog> allLogs = new ArrayList<>();
        
        // IP -> rootNodeId 映射（用于桥接网侧和端侧）
        Map<String, String> ipToRootNodeIdMap = new HashMap<>();

        try {
            log.info("【进程链生成】-> ========================================");
            log.info("【进程链生成】-> 开始批量生成进程链，IP数量: {}, 网端关联数: {}", 
                    ips.size(), ipMappingRelation.getAlarmIps().size());
            log.info("【进程链生成】-> ========================================");

            // 性能优化：批量查询所有IP的告警数据
            long startTime = System.currentTimeMillis();
            Map<String, List<RawAlarm>> allAlarmsMap = esQueryService.batchQueryEDRAlarms(ips);
            long queryTime = System.currentTimeMillis() - startTime;
            log.info("【进程链生成】-> 批量告警查询完成，耗时: {}ms", queryTime);

            // 为每个IP选择告警和查询日志
            int successCount = 0;
            int failureCount = 0;
            int associatedCount = 0;
            String firstTraceId = null;

            // ========== 阶段1: 选择所有告警 ==========
            Map<String, String> hostToTraceId = new HashMap<>();
            for (String ip : ips) {
                try {
                    log.info("【进程链生成】-> 处理IP: {}", ip);

                    // 检查是否有网端关联
                    boolean hasAssociation = ipMappingRelation.hasAssociation(ip);
                    String associatedEventId = ipMappingRelation.getAssociatedEventId(ip);
                    
                    if (hasAssociation) {
                        log.info("【进程链生成】-> IP [{}] 有网端关联，关联告警ID: {}", ip, associatedEventId);
                        associatedCount++;
                    }

                    List<RawAlarm> alarms = allAlarmsMap.getOrDefault(ip, new ArrayList<>());
                    if (alarms.isEmpty()) {
                        log.warn("【进程链生成】-> IP [{}] 没有查询到告警数据，跳过", ip);
                        failureCount++;
                        continue;
                    }

                    // 选择告警（返回同一个traceId的所有告警）
                    List<RawAlarm> selectedAlarms = selectAlarm(alarms, associatedEventId, hasAssociation);
                    if (selectedAlarms == null || selectedAlarms.isEmpty()) {
                        log.warn("【进程链生成】-> IP [{}] 无法选择有效告警，跳过", ip);
                        failureCount++;
                        continue;
                    }

                    // 使用第一个告警获取基本信息
                    RawAlarm firstAlarm = selectedAlarms.get(0);
                    log.info("【进程链生成】-> 选中 {} 个告警: traceId={}, eventId={}, 网端关联={}", 
                            selectedAlarms.size(), firstAlarm.getTraceId(), firstAlarm.getEventId(), hasAssociation);

                    // 记录日志ID（如果有）
                    String logId = ipMappingRelation.getLogId(ip);
                    if (logId != null && !logId.trim().isEmpty()) {
                        log.debug("【进程链生成】-> IP [{}] 有预存的日志ID: {}", ip, logId);
                    }

                    // 收集所有选中的告警
                    allSelectedAlarms.addAll(selectedAlarms);
                    
                    // 记录第一个traceId用于构建
                    if (firstTraceId == null) {
                        firstTraceId = firstAlarm.getTraceId();
                    }
                    // 记录 host -> traceId 的映射（一个IP一个traceId）
                    if (firstAlarm.getHostAddress() != null && firstAlarm.getTraceId() != null) {
                        hostToTraceId.put(firstAlarm.getHostAddress(), firstAlarm.getTraceId());
                    }
                    
                    successCount++;
                    log.info("【进程链生成】-> IP [{}] 告警已选择", ip);

                } catch (Exception e) {
                    log.error("【进程链生成】-> IP [{}] 处理失败: {}", ip, e.getMessage(), e);
                    failureCount++;
                }
            }
            
            // ========== 阶段2: 批量查询所有日志 ==========
            if (!hostToTraceId.isEmpty()) {
                try {
                    // 使用 host->traceId 映射进行批量查询（MultiSearchRequest方式，每个host查询其对应的traceId）
                    long logQueryStart = System.currentTimeMillis();
                    allLogs = esQueryService.batchQueryRawLogs(hostToTraceId);
                    long logQueryTime = System.currentTimeMillis() - logQueryStart;
                    
                    log.info("【进程链生成】-> 批量日志查询完成: host-traceId映射数={}, 日志总数={}, 耗时={}ms", 
                            hostToTraceId.size(), allLogs.size(), logQueryTime);
                } catch (Exception e) {
                    log.error("【进程链生成】-> 批量查询日志失败: {}", e.getMessage(), e);
                    allLogs = new ArrayList<>();
                }
            }

            // ========== 阶段3: 构建端侧进程链 ==========
            ProcessChainBuilder builder = new ProcessChainBuilder();
            IncidentProcessChain endpointChain = builder.buildIncidentChain(
                    allSelectedAlarms, allLogs, firstTraceId, null,
                    IncidentConverters.NODE_MAPPER, IncidentConverters.EDGE_MAPPER);
            
            // ========== 阶段4: 构建 IP -> rootNodeId 映射 ==========
            if (endpointChain != null && endpointChain.getNodes() != null) {
                for (ProcessNode node : endpointChain.getNodes()) {
                    if (isRootNode(node)) {
                        // 通过 hostToTraceId 反向查找该根节点对应的 IP
                        String nodeIp = findIpForRootNode(node, hostToTraceId, allSelectedAlarms);
                        if (nodeIp != null && !nodeIp.isEmpty()) {
                            ipToRootNodeIdMap.put(nodeIp, node.getNodeId());
                            log.info("【进程链生成】-> 根节点映射: IP={}, rootNodeId={}", nodeIp, node.getNodeId());
                        }
                    }
                }
            }
            
            long totalTime = System.currentTimeMillis() - startTime;
            log.info("【进程链生成】-> ========================================");
            log.info("【进程链生成】-> 端侧进程链生成完成");
            log.info("【进程链生成】-> 总耗时: {}ms", totalTime);
            log.info("【进程链生成】-> 成功: {}, 失败: {}, 网端关联: {}", successCount, failureCount, associatedCount);
            log.info("【进程链生成】-> 节点数: {}, 边数: {}", 
                    endpointChain != null && endpointChain.getNodes() != null ? endpointChain.getNodes().size() : 0,
                    endpointChain != null && endpointChain.getEdges() != null ? endpointChain.getEdges().size() : 0);
            log.info("【进程链生成】-> 根节点映射数: {}", ipToRootNodeIdMap.size());
            log.info("【进程链生成】-> ========================================");

            // ========== 阶段5: 合并网侧和端侧 ==========
            if (networkChain == null || networkChain.getKey() == null || networkChain.getKey().isEmpty()) {
                log.info("【进程链生成】-> 没有网侧数据，直接返回端侧进程链");
                return endpointChain;
            }
            
            // 合并网侧和端侧进程链
            return mergeNetworkAndEndpointChain(networkChain, endpointChain, ipToRootNodeIdMap);

        } catch (Exception e) {
            log.error("【进程链生成】-> 批量生成进程链失败: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * 为单个IP生成进程链
     */
    public IncidentProcessChain generateProcessChainForIp(String ip, String associatedEventId, boolean hasAssociation) {
        if (ip == null || ip.trim().isEmpty()) {
            log.error("【进程链生成】-> 错误: IP为空");
            return null;
        }

        try {
            log.info("【进程链生成】-> 为IP生成进程链: {}, 网端关联: {}", ip, hasAssociation);

            // 查询告警
            List<RawAlarm> alarms = esQueryService.queryEDRAlarms(ip);
            if (alarms == null || alarms.isEmpty()) {
                log.warn("【进程链生成】-> IP [{}] 没有查询到告警数据", ip);
                return null;
            }

            // 选择告警（返回同一个traceId的所有告警）
            List<RawAlarm> selectedAlarms = selectAlarm(alarms, associatedEventId, hasAssociation);
            if (selectedAlarms == null || selectedAlarms.isEmpty()) {
                log.warn("【进程链生成】-> IP [{}] 无法选择有效告警", ip);
                return null;
            }

            // 使用第一个告警的信息查询日志和设置基本信息
            RawAlarm firstAlarm = selectedAlarms.get(0);

            // 查询日志
            List<RawLog> logs = queryLogsForAlarm(firstAlarm);

            // 构建进程链（传入所有选中的告警）
            ProcessChainBuilder builder = new ProcessChainBuilder();
            IncidentProcessChain incidentChain = builder.buildIncidentChain(
                selectedAlarms,  // 所有告警
                logs, 
                firstAlarm.getTraceId(), 
                associatedEventId,
                IncidentConverters.NODE_MAPPER, 
                IncidentConverters.EDGE_MAPPER);
            
            // 设置基本信息
            if (incidentChain != null) {
                incidentChain.setTraceId(firstAlarm.getTraceId());
                incidentChain.setHostAddress(firstAlarm.getHostAddress());
            }
            
            return incidentChain;

        } catch (Exception e) {
            log.error("【进程链生成】-> 生成进程链失败: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * 选择告警（返回同一个traceId的所有告警）
     * 优先使用网端关联告警的traceId，否则使用选举算法选择traceId
     * 
     * @param alarms 告警列表
     * @param associatedEventId 关联事件ID
     * @param hasAssociation 是否有网端关联
     * @return 选中的traceId对应的所有告警
     */
    private List<RawAlarm> selectAlarm(List<RawAlarm> alarms, String associatedEventId, boolean hasAssociation) {
        if (alarms == null || alarms.isEmpty()) {
            log.warn("【进程链生成】-> 告警列表为空");
            return new ArrayList<>();
        }

        String selectedTraceId = null;

        // 场景1: 有网端关联，优先选择关联的告警对应的traceId
        if (hasAssociation && associatedEventId != null && !associatedEventId.trim().isEmpty()) {
            for (RawAlarm alarm : alarms) {
                if (associatedEventId.equals(alarm.getEventId())) {
                    selectedTraceId = alarm.getTraceId();
                    log.info("【进程链生成】-> 网端关联成功，选择告警 eventId={}, traceId={}", associatedEventId, selectedTraceId);
                    break;
                }
            }
            
            if (selectedTraceId == null) {
                log.warn("【进程链生成】-> 未找到网端关联告警 [eventId={}]，降级使用选举算法", associatedEventId);
            }
        }

        // 场景2: 没有网端关联或关联失败，使用选举算法
        if (selectedTraceId == null) {
        // 按traceId分组
        Map<String, List<RawAlarm>> alarmGroups = groupAlarmsByTraceId(alarms);

            // 使用选举算法选择最佳traceId
            selectedTraceId = AlarmElectionUtil.electAlarm(alarmGroups);
        if (selectedTraceId == null) {
                log.error("【进程链生成】-> 告警选举失败");
                return new ArrayList<>();
            }
            
            log.info("【进程链生成】-> 选举算法选中 traceId={}", selectedTraceId);
        }

        // 返回选中traceId的所有告警
        List<RawAlarm> selectedAlarms = new ArrayList<>();
        for (RawAlarm alarm : alarms) {
            if (selectedTraceId.equals(alarm.getTraceId())) {
                selectedAlarms.add(alarm);
            }
        }

        log.info("【进程链生成】-> 选择了 traceId={} 的 {} 个告警", selectedTraceId, selectedAlarms.size());
        return selectedAlarms;
    }

    /**
     * 按traceId分组告警
     */
    private Map<String, List<RawAlarm>> groupAlarmsByTraceId(List<RawAlarm> alarms) {
        Map<String, List<RawAlarm>> groups = new HashMap<>();

        if (alarms == null) {
            return groups;
        }

        for (RawAlarm alarm : alarms) {
            if (alarm == null || alarm.getTraceId() == null) {
                continue;
            }
            groups.computeIfAbsent(alarm.getTraceId(), k -> new ArrayList<>()).add(alarm);
        }

        return groups;
    }

    /**
     * 查询告警相关的日志
     */
    private List<RawLog> queryLogsForAlarm(RawAlarm alarm) {
        if (alarm == null || alarm.getTraceId() == null) {
            return new ArrayList<>();
        }

        try {
            String timeStart = alarm.getStartTime();
            String timeEnd = calculateEndTime(timeStart);

            // 关注的日志类型
            List<String> logTypes = ProcessChainConstants.LogType.ALL_MONITORED_TYPES;

            return esQueryService.queryRawLogs(
                alarm.getTraceId(),
                alarm.getHostAddress(),
                timeStart,
                timeEnd,
                logTypes
            );

        } catch (Exception e) {
            log.error("【进程链生成】-> 查询告警日志失败: {}", e.getMessage(), e);
            return new ArrayList<>();
        }
    }

    /**
     * 计算结束时间（告警开始时间+默认时间窗口）
     */
    private String calculateEndTime(String startTime) {
        return TimeUtil.addHours(startTime, ProcessChainConstants.Time.DEFAULT_TIME_WINDOW_HOURS);
    }
    
    /**
     * 判断节点是否是根节点
     */
    private boolean isRootNode(ProcessNode node) {
        return node.getIsChainNode() != null 
                && node.getIsChainNode() 
                && node.getChainNode() != null 
                && node.getChainNode().getIsRoot() != null 
                && node.getChainNode().getIsRoot();
    }
    
    /**
     * 查找根节点对应的 IP
     * 通过根节点的 processGuid 匹配告警中的 processGuid，然后获取 hostAddress
     * 
     * @param rootNode 根节点
     * @param hostToTraceId host到traceId的映射
     * @param allAlarms 所有告警列表
     * @return 对应的IP地址，如果找不到返回null
     */
    private String findIpForRootNode(ProcessNode rootNode, 
                                      Map<String, String> hostToTraceId,
                                      List<RawAlarm> allAlarms) {
        String rootNodeId = rootNode.getNodeId(); // 这是 processGuid
        
        // 在告警列表中查找匹配的告警
        for (RawAlarm alarm : allAlarms) {
            if (alarm.getProcessGuid() != null && alarm.getProcessGuid().equals(rootNodeId)) {
                String ip = alarm.getHostAddress();
                log.debug("【进程链生成】-> 根节点 {} 对应IP: {}", rootNodeId, ip);
                return ip;
            }
        }
        
        // 如果告警中没找到，尝试通过 traceId 反向查找
        // 如果根节点的 processGuid == traceId，可以通过 hostToTraceId 反向查找
        for (Map.Entry<String, String> entry : hostToTraceId.entrySet()) {
            if (entry.getValue().equals(rootNodeId)) {
                String ip = entry.getKey();
                log.debug("【进程链生成】-> 通过traceId匹配，根节点 {} 对应IP: {}", rootNodeId, ip);
                return ip;
            }
        }
        
        log.warn("【进程链生成】-> 无法找到根节点 {} 对应的IP", rootNodeId);
        return null;
    }
    
    /**
     * 合并网侧和端侧进程链
     * 
     * @param networkChain 网侧进程链（包含节点和边）
     * @param endpointChain 端侧进程链
     * @param ipToRootNodeIdMap IP到端侧根节点ID的映射
     * @return 合并后的完整进程链
     */
    private IncidentProcessChain mergeNetworkAndEndpointChain(
            Pair<List<ProcessNode>, List<ProcessEdge>> networkChain,
            IncidentProcessChain endpointChain,
            Map<String, String> ipToRootNodeIdMap) {
        
        log.info("【进程链生成】-> ========================================");
        log.info("【进程链生成】-> 开始合并网侧和端侧进程链");
        
        IncidentProcessChain mergedChain = new IncidentProcessChain();
        List<ProcessNode> allNodes = new ArrayList<>();
        List<ProcessEdge> allEdges = new ArrayList<>();
        
        try {
            // 1. 添加网侧节点（storyNode）
            List<ProcessNode> networkNodes = networkChain.getKey();
            if (networkNodes != null && !networkNodes.isEmpty()) {
                allNodes.addAll(networkNodes);
                log.info("【进程链生成】-> 添加网侧节点数: {}", networkNodes.size());
            }
            
            // 2. 添加端侧节点（chainNode）
            if (endpointChain != null && endpointChain.getNodes() != null) {
                allNodes.addAll(endpointChain.getNodes());
                log.info("【进程链生成】-> 添加端侧节点数: {}", endpointChain.getNodes().size());
            }
            
            // 3. 添加网侧边
            List<ProcessEdge> networkEdges = networkChain.getValue();
            if (networkEdges != null && !networkEdges.isEmpty()) {
                allEdges.addAll(networkEdges);
                log.info("【进程链生成】-> 添加网侧边数: {}", networkEdges.size());
            }
            
            // 4. 添加端侧边
            if (endpointChain != null && endpointChain.getEdges() != null) {
                allEdges.addAll(endpointChain.getEdges());
                log.info("【进程链生成】-> 添加端侧边数: {}", endpointChain.getEdges().size());
            }
            
            // 5. **关键**：创建桥接边（连接网侧 victim 到端侧根节点）
            List<ProcessEdge> bridgeEdges = createBridgeEdges(networkNodes, ipToRootNodeIdMap);
            if (bridgeEdges != null && !bridgeEdges.isEmpty()) {
                allEdges.addAll(bridgeEdges);
                log.info("【进程链生成】-> 添加桥接边数: {}", bridgeEdges.size());
            }
            
            // 6. 设置合并结果
            mergedChain.setNodes(allNodes);
            mergedChain.setEdges(allEdges);
            
            // 7. 设置基本信息（使用端侧的信息）
            if (endpointChain != null) {
                mergedChain.setTraceId(endpointChain.getTraceId());
                mergedChain.setHostAddress(endpointChain.getHostAddress());
                mergedChain.setThreatSeverity(endpointChain.getThreatSeverity());
            }
            
            log.info("【进程链生成】-> 进程链合并完成");
            log.info("【进程链生成】-> 总节点数: {}, 总边数: {}", allNodes.size(), allEdges.size());
            log.info("【进程链生成】-> ========================================");
            
        } catch (Exception e) {
            log.error("【进程链生成】-> 合并进程链失败: {}", e.getMessage(), e);
            return endpointChain; // 失败时返回端侧链
        }
        
        return mergedChain;
    }
    
    /**
     * 创建网侧到端侧的桥接边
     * 
     * 核心逻辑：
     * 1. 遍历网侧节点，找到所有 victim 类型节点（storyNode.type === "victim"）
     * 2. 从 storyNode.other.ip 提取 victim 的 IP
     * 3. 在 ipToRootNodeIdMap 中查找对应的端侧根节点ID
     * 4. 如果找到，创建桥接边（source=victim.nodeId, target=rootNodeId）
     * 
     * @param networkNodes 网侧节点列表
     * @param ipToRootNodeIdMap IP到端侧根节点ID的映射
     * @return 桥接边列表
     */
    private List<ProcessEdge> createBridgeEdges(
            List<ProcessNode> networkNodes,
            Map<String, String> ipToRootNodeIdMap) {
        
        List<ProcessEdge> bridgeEdges = new ArrayList<>();
        
        if (networkNodes == null || networkNodes.isEmpty()) {
            log.debug("【进程链生成】-> 网侧节点为空，无需创建桥接边");
            return bridgeEdges;
        }
        
        if (ipToRootNodeIdMap == null || ipToRootNodeIdMap.isEmpty()) {
            log.warn("【进程链生成】-> 端侧根节点映射为空，无法创建桥接边");
            return bridgeEdges;
        }
        
        log.info("【进程链生成】-> 开始创建桥接边，网侧节点数: {}, 端侧根节点映射数: {}", 
                networkNodes.size(), ipToRootNodeIdMap.size());
        
        int victimCount = 0;
        int bridgedCount = 0;
        
        // 遍历网侧节点
        for (ProcessNode networkNode : networkNodes) {
            // 跳过进程链节点，只处理故事节点
            if (networkNode.getIsChainNode() != null && networkNode.getIsChainNode()) {
                continue;
            }
            
            if (networkNode.getStoryNode() == null) {
                continue;
            }
            
            StoryNode storyNode = networkNode.getStoryNode();
            String type = storyNode.getType();
            
            // 只处理 victim 类型的节点
            if (!"victim".equals(type)) {
                continue;
            }
            
            victimCount++;
            
            // 从 storyNode.other.ip 提取 IP（统一从这里获取）
            String victimIp = extractIpFromStoryNode(storyNode);
            
            if (victimIp == null || victimIp.isEmpty()) {
                log.warn("【进程链生成】-> 无法从 victim 节点提取IP: nodeId={}", networkNode.getNodeId());
                continue;
            }
            
            // 查找端侧对应的根节点ID
            String rootNodeId = ipToRootNodeIdMap.get(victimIp);
            
            if (rootNodeId == null || rootNodeId.isEmpty()) {
                log.debug("【进程链生成】-> IP [{}] 在端侧没有对应的根节点，跳过桥接", victimIp);
                continue;
            }
            
            // 创建桥接边
            ProcessEdge bridgeEdge = new ProcessEdge();
            bridgeEdge.setSource(networkNode.getNodeId());  // victim 的 nodeId（可能是 "victim" 或 IP）
            bridgeEdge.setTarget(rootNodeId);               // 端侧根节点的 nodeId（processGuid）
            bridgeEdge.setVal("");                          // 透传，不设置特定值
            
            bridgeEdges.add(bridgeEdge);
            bridgedCount++;
            
            log.info("【进程链生成】-> 创建桥接边 #{}: source={}, target={}, IP={}", 
                    bridgedCount, networkNode.getNodeId(), rootNodeId, victimIp);
        }
        
        log.info("【进程链生成】-> 桥接边创建完成: 发现victim节点={}, 成功创建桥接边={}", 
                victimCount, bridgedCount);
        
        return bridgeEdges;
    }
    
    /**
     * 从 StoryNode 中提取 IP 地址
     * 统一从 storyNode.other.ip 获取（无论 nodeId 是什么）
     */
    private String extractIpFromStoryNode(StoryNode storyNode) {
        if (storyNode == null || storyNode.getOther() == null) {
            return null;
        }
        
        Object ipObj = storyNode.getOther().get("ip");
        if (ipObj != null) {
            String ip = ipObj.toString().trim();
            log.debug("【进程链生成】-> 从 storyNode.other.ip 提取IP: {}", ip);
            return ip;
        }
        
                return null;
    }
}

