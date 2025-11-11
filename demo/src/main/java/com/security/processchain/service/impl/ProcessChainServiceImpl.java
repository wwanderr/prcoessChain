package com.security.processchain.service.impl;

import com.security.processchain.model.IpMappingRelation;
import com.security.processchain.model.ProcessEdge;
import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.*;
import com.security.processchain.util.AlarmElectionUtil;
import com.security.processchain.util.Pair;
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
        
        // 收集所有的 traceId、hostAddress 和 associatedEventId
        Set<String> allTraceIds = new HashSet<>();
        Set<String> allHostAddresses = new HashSet<>();
        Set<String> allAssociatedEventIds = new HashSet<>();

        try {
            log.info("【进程链生成】-> ========================================");
            int alarmIpsCount = (ipMappingRelation.getAlarmIps() != null) ? ipMappingRelation.getAlarmIps().size() : 0;
            log.info("【进程链生成】-> 开始批量生成进程链，IP数量: {}, 网端关联数: {}", 
                    ips.size(), alarmIpsCount);
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

            // ========== 阶段1: 选择所有告警 ==========
            Map<String, String> hostToTraceId = new HashMap<>();
            Map<String, String> hostToStartTime = new HashMap<>();  // 记录每个host的告警startTime（用于时间范围查询）
            for (String ip : ips) {
                try {
                    log.info("【进程链生成】-> 处理IP: {}", ip);

                    // 检查是否有网端关联
                    boolean hasAssociation = ipMappingRelation.hasAssociation(ip);
                    String associatedEventId = ipMappingRelation.getAssociatedEventId(ip);
                    
                    if (hasAssociation) {
                        log.info("【进程链生成】-> IP [{}] 有网端关联，关联告警ID: {}", ip, associatedEventId);
                        associatedCount++;
                        
                        // 收集 associatedEventId
                        if (associatedEventId != null && !associatedEventId.trim().isEmpty()) {
                            allAssociatedEventIds.add(associatedEventId);
                        }
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
                    
                    // 收集所有 traceId 和 hostAddress
                    if (firstAlarm.getTraceId() != null) {
                        allTraceIds.add(firstAlarm.getTraceId());
                    }
                    if (firstAlarm.getHostAddress() != null) {
                        allHostAddresses.add(firstAlarm.getHostAddress());
                    }
                    
                    // 记录 host -> traceId 的映射（一个IP一个traceId）
                    if (firstAlarm.getHostAddress() != null && firstAlarm.getTraceId() != null) {
                        hostToTraceId.put(firstAlarm.getHostAddress(), firstAlarm.getTraceId());
                        
                        // 记录 host -> startTime 的映射（因为告警已按startTime降序排序，第一个就是最新的）
                        if (firstAlarm.getStartTime() != null) {
                            hostToStartTime.put(firstAlarm.getHostAddress(), firstAlarm.getStartTime());
                            log.debug("【进程链生成】-> IP [{}] 告警时间: {}", firstAlarm.getHostAddress(), firstAlarm.getStartTime());
                        }
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
                    // 使用 host->traceId 映射进行批量查询，带时间范围过滤（告警startTime前后10分钟）
                    long logQueryStart = System.currentTimeMillis();
                    allLogs = esQueryService.batchQueryRawLogsWithTimeRange(hostToTraceId, hostToStartTime);
                    long logQueryTime = System.currentTimeMillis() - logQueryStart;
                    
                    log.info("【进程链生成】-> 批量日志查询完成（带时间范围）: host-traceId映射数={}, 日志总数={}, 耗时={}ms", 
                            hostToTraceId.size(), allLogs.size(), logQueryTime);
                } catch (Exception e) {
                    log.error("【进程链生成】-> 批量查询日志失败: {}", e.getMessage(), e);
                    allLogs = new ArrayList<>();
                }
            }

            // ========== 阶段3: 构建端侧进程链 ==========
            log.info("【进程链生成】-> 收集到的 traceId 数量: {}, hostAddress 数量: {}, associatedEventId 数量: {}", 
                    allTraceIds.size(), allHostAddresses.size(), allAssociatedEventIds.size());
            log.info("【进程链生成】-> traceIds: {}", allTraceIds);
            log.info("【进程链生成】-> associatedEventIds: {}", allAssociatedEventIds);
            
            ProcessChainBuilder builder = new ProcessChainBuilder();
            IncidentProcessChain endpointChain = builder.buildIncidentChain(
                    allSelectedAlarms, allLogs, allTraceIds, allAssociatedEventIds,
                    IncidentConverters.NODE_MAPPER, IncidentConverters.EDGE_MAPPER);
            
            // ✅ 优化：单独获取 traceIdToRootNodeMap（不作为 IncidentProcessChain 的一部分）
            Map<String, String> traceIdToRootNodeMap = builder.getTraceIdToRootNodeMap();
            
            // 设置 traceIds 和 hostAddresses
            if (endpointChain != null) {
                endpointChain.setTraceIds(new ArrayList<>(allTraceIds));
                endpointChain.setHostAddresses(new ArrayList<>(allHostAddresses));
            }
            
            long totalTime = System.currentTimeMillis() - startTime;
            log.info("【进程链生成】-> ========================================");
            log.info("【进程链生成】-> 端侧进程链生成完成");
            log.info("【进程链生成】-> 总耗时: {}ms", totalTime);
            log.info("【进程链生成】-> 成功: {}, 失败: {}, 网端关联: {}", successCount, failureCount, associatedCount);
            log.info("【进程链生成】-> 节点数: {}, 边数: {}", 
                    endpointChain != null && endpointChain.getNodes() != null ? endpointChain.getNodes().size() : 0,
                    endpointChain != null && endpointChain.getEdges() != null ? endpointChain.getEdges().size() : 0);
            if (traceIdToRootNodeMap != null && !traceIdToRootNodeMap.isEmpty()) {
                log.info("【进程链生成】-> traceId到根节点映射数: {}", traceIdToRootNodeMap.size());
                log.info("【进程链生成】-> traceId映射详情: {}", traceIdToRootNodeMap);
            }
            log.info("【进程链生成】-> ========================================");

            // ========== 阶段4: 合并网侧和端侧 ==========
            if (networkChain == null || networkChain.getKey() == null || networkChain.getKey().isEmpty()) {
                log.info("【进程链生成】-> 没有网侧数据，直接返回端侧进程链");
                
                // ========== 计算端侧节点的子节点数量 ==========
                if (endpointChain != null && endpointChain.getNodes() != null && endpointChain.getEdges() != null) {
                    com.security.processchain.util.ProcessChainExtensionUtil.calculateChildrenCount(
                            endpointChain.getNodes(), endpointChain.getEdges());
                    log.info("【进程链生成】-> 子节点数量计算完成");
                }
                
                return endpointChain;
            }
            
            // ✅ 优化：将 traceIdToRootNodeMap 作为参数传递，而不是从 IncidentProcessChain 中获取
            return mergeNetworkAndEndpointChain(networkChain, endpointChain, hostToTraceId, traceIdToRootNodeMap);

        } catch (Exception e) {
            log.error("【进程链生成】-> 批量生成进程链失败: {}", e.getMessage(), e);
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
     * 合并网侧和端侧进程链
     * 
     * @param networkChain 网侧进程链（包含节点和边）
     * @param endpointChain 端侧进程链
     * @param hostToTraceId host到traceId的映射
     * @param traceIdToRootNodeMap traceId到根节点ID的映射（用于创建桥接边）
     * @return 合并后的完整进程链
     */
    private IncidentProcessChain mergeNetworkAndEndpointChain(
            Pair<List<ProcessNode>, List<ProcessEdge>> networkChain,
            IncidentProcessChain endpointChain,
            Map<String, String> hostToTraceId,
            Map<String, String> traceIdToRootNodeMap) {
        
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
            
            // ========== 5. 扩展溯源（新增功能）==========
            Map<String, String> finalRootMap = com.security.processchain.util.ProcessChainExtensionUtil.performExtension(
                    traceIdToRootNodeMap, hostToTraceId, allNodes, allEdges, esQueryService, 2);
            
            // 6. **关键**：创建桥接边（连接网侧 victim 到端侧根节点）
            // 使用更新后的映射创建桥接边
            if (finalRootMap != null && !finalRootMap.isEmpty()) {
                BridgeResult bridgeResult = createBridgeEdges(
                        networkNodes,
                        networkEdges,  // 新增：传入网侧边列表，用于判断 victim 是否为 source
                        hostToTraceId, 
                        finalRootMap);
                
                // 添加虚拟节点到 allNodes
                if (bridgeResult.getVirtualNodes() != null && !bridgeResult.getVirtualNodes().isEmpty()) {
                    allNodes.addAll(bridgeResult.getVirtualNodes());
                    log.info("【进程链生成】-> 添加虚拟节点数: {}", bridgeResult.getVirtualNodes().size());
                }
                
                // 添加桥接边到 allEdges
                if (bridgeResult.getBridgeEdges() != null && !bridgeResult.getBridgeEdges().isEmpty()) {
                    allEdges.addAll(bridgeResult.getBridgeEdges());
                    log.info("【进程链生成】-> 添加桥接边数: {}", bridgeResult.getBridgeEdges().size());
                }
            } else {
                log.warn("【进程链生成】-> 桥接映射为空，无法创建桥接边");
            }
            
            // 7. 设置合并结果
            mergedChain.setNodes(allNodes);
            mergedChain.setEdges(allEdges);
            
            // ========== 8. 计算每个节点的子节点数量 ==========
            // 在所有节点和边都添加完成后，统一计算子节点数量
            // 这样可以涵盖：端侧节点、网侧节点、扩展节点、桥接边
            com.security.processchain.util.ProcessChainExtensionUtil.calculateChildrenCount(
                    allNodes, allEdges);
            log.info("【进程链生成】-> 子节点数量计算完成");
            
            // 9. 设置基本信息（使用端侧的信息）
            if (endpointChain != null) {
                mergedChain.setTraceIds(endpointChain.getTraceIds());
                mergedChain.setHostAddresses(endpointChain.getHostAddresses());
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
     * 桥接结果（包含虚拟节点和桥接边）
     */
    private static class BridgeResult {
        private final List<ProcessNode> virtualNodes;
        private final List<ProcessEdge> bridgeEdges;
        
        public BridgeResult(List<ProcessNode> virtualNodes, List<ProcessEdge> bridgeEdges) {
            this.virtualNodes = virtualNodes != null ? virtualNodes : new ArrayList<>();
            this.bridgeEdges = bridgeEdges != null ? bridgeEdges : new ArrayList<>();
        }
        
        public List<ProcessNode> getVirtualNodes() {
            return virtualNodes;
        }
        
        public List<ProcessEdge> getBridgeEdges() {
            return bridgeEdges;
        }
    }
    
    /**
     * 创建网侧到端侧的桥接边（优化版：支持虚拟节点）
     * 
     * 核心逻辑：
     * 1. 遍历网侧节点，找到所有 victim 类型节点（storyNode.type === "victim"）
     * 2. 判断 victim 是否在网侧边中作为 source（即 victim -> 其他节点）
     * 3. 如果 victim 是 source：
     *    - 创建虚拟节点（logType="virtual"）
     *    - 创建两条边：victim -> 虚拟节点 -> 端侧根节点
     * 4. 如果 victim 不是 source（只是 target）：
     *    - 直接创建桥接边：victim -> 端侧根节点
     * 
     * @param networkNodes 网侧节点列表
     * @param networkEdges 网侧边列表（用于判断 victim 是否为 source）
     * @param hostToTraceId host到traceId的映射
     * @param traceIdToRootNodeMap traceId到根节点ID的映射
     * @return 桥接结果（包含虚拟节点和桥接边）
     */
    private BridgeResult createBridgeEdges(
            List<ProcessNode> networkNodes,
            List<ProcessEdge> networkEdges,
            Map<String, String> hostToTraceId,
            Map<String, String> traceIdToRootNodeMap) {
        
        List<ProcessNode> virtualNodes = new ArrayList<>();
        List<ProcessEdge> bridgeEdges = new ArrayList<>();
        
        if (networkNodes == null || networkNodes.isEmpty()) {
            log.debug("【进程链生成】-> 网侧节点为空，无需创建桥接边");
            return new BridgeResult(virtualNodes, bridgeEdges);
        }
        
        if (hostToTraceId == null || hostToTraceId.isEmpty()) {
            log.warn("【进程链生成】-> hostToTraceId 映射为空，无法创建桥接边");
            return new BridgeResult(virtualNodes, bridgeEdges);
        }
        
        if (traceIdToRootNodeMap == null || traceIdToRootNodeMap.isEmpty()) {
            log.warn("【进程链生成】-> traceIdToRootNodeMap 映射为空，无法创建桥接边");
            return new BridgeResult(virtualNodes, bridgeEdges);
        }
        
        // ========== 步骤1：构建所有在网侧边中作为 source 的节点集合 ==========
        // 注意：这个集合包含所有类型的节点（attacker、victim、server等），不仅仅是 victim
        // 后续会通过遍历 victim 节点并检查其 nodeId 是否在此集合中，来判断该 victim 是否为 source
        Set<String> nodesAsSourceSet = new HashSet<>();
        if (networkEdges != null) {
            for (ProcessEdge edge : networkEdges) {
                if (edge != null && edge.getSource() != null) {
                    nodesAsSourceSet.add(edge.getSource());
                }
            }
        }
        log.debug("【进程链生成】-> 网侧边中作为 source 的节点数: {}", nodesAsSourceSet.size());
        
        log.info("【进程链生成】-> 开始创建桥接边，网侧节点数: {}, hostToTraceId映射数: {}, traceIdToRootNode映射数: {}", 
                networkNodes.size(), hostToTraceId.size(), traceIdToRootNodeMap.size());
        log.info("【进程链生成】-> hostToTraceId详情: {}", hostToTraceId);
        log.info("【进程链生成】-> traceIdToRootNodeMap详情: {}", traceIdToRootNodeMap);
        
        int victimCount = 0;
        int bridgedCount = 0;
        int virtualNodeCount = 0;
        
        // ========== 步骤2：遍历网侧节点，处理 victim 节点 ==========
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
            String victimNodeId = networkNode.getNodeId();
            
            // 步骤2.1: 从 storyNode.other.ip 提取 IP
            String victimIp = extractIpFromStoryNode(storyNode);
            
            if (victimIp == null || victimIp.isEmpty()) {
                log.warn("【进程链生成】-> ❌ 无法从 victim 节点提取IP: nodeId={}", victimNodeId);
                continue;
            }
            
            log.debug("【进程链生成】-> victim节点 {} 的IP: {}", victimNodeId, victimIp);
            
            // 步骤2.2: 通过 IP 查找 traceId
            String traceId = hostToTraceId.get(victimIp);
            
            if (traceId == null || traceId.isEmpty()) {
                log.warn("【进程链生成】-> ❌ IP [{}] 在 hostToTraceId 中没有对应的 traceId，跳过桥接", victimIp);
                continue;
            }
            
            log.debug("【进程链生成】-> IP {} 对应的 traceId: {}", victimIp, traceId);
            
            // 步骤2.3: 通过 traceId 查找根节点ID
            String rootNodeId = traceIdToRootNodeMap.get(traceId);
            
            if (rootNodeId == null || rootNodeId.isEmpty()) {
                log.warn("【进程链生成】-> ❌ traceId [{}] 在 traceIdToRootNodeMap 中没有对应的根节点，跳过桥接", traceId);
                continue;
            }
            
            log.debug("【进程链生成】-> traceId {} 对应的根节点: {}", traceId, rootNodeId);
            
            // ========== 步骤3：判断 victim 是否为 source ==========
            // 检查当前 victim 的 nodeId 是否在网侧边中作为 source
            boolean isSource = nodesAsSourceSet.contains(victimNodeId);
            
            if (isSource) {
                // ========== 场景A：victim 是 source，需要创建虚拟节点 ==========
                log.info("【进程链生成】-> victim节点 {} 在网侧边中作为 source，创建虚拟节点", victimNodeId);
                
                // 创建虚拟节点
                ProcessNode virtualNode = createVirtualNode(victimNodeId, victimIp);
                virtualNodes.add(virtualNode);
                virtualNodeCount++;
                
                // 创建两条边：victim -> 虚拟节点 -> 端侧根节点
                // 边1: victim -> 虚拟节点
                ProcessEdge edge1 = new ProcessEdge();
                edge1.setSource(victimNodeId);
                edge1.setTarget(virtualNode.getNodeId());
                edge1.setVal("桥接");
                bridgeEdges.add(edge1);
                
                // 边2: 虚拟节点 -> 端侧根节点
                ProcessEdge edge2 = new ProcessEdge();
                edge2.setSource(virtualNode.getNodeId());
                edge2.setTarget(rootNodeId);
                edge2.setVal("桥接");
                bridgeEdges.add(edge2);
                
                bridgedCount += 2; // 创建了2条边
                
                log.info("【进程链生成】-> ✅ 创建虚拟节点和桥接边: victim={}, virtualNode={}, rootNode={}, IP={}, traceId={}", 
                        victimNodeId, virtualNode.getNodeId(), rootNodeId, victimIp, traceId);
            } else {
                // ========== 场景B：victim 不是 source（只是 target），直接桥接 ==========
                ProcessEdge bridgeEdge = new ProcessEdge();
                bridgeEdge.setSource(victimNodeId);
                bridgeEdge.setTarget(rootNodeId);
                bridgeEdge.setVal("桥接");
                bridgeEdges.add(bridgeEdge);
                bridgedCount++;
                
                log.info("【进程链生成】-> ✅ 创建桥接边: source={}, target={}, IP={}, traceId={}", 
                        victimNodeId, rootNodeId, victimIp, traceId);
            }
        }
        
        // 最终统计
        if (bridgedCount == 0 && victimCount > 0) {
            log.error("【进程链生成】-> ❌❌❌ 发现了 {} 个victim节点，但没有创建任何桥接边！", victimCount);
            log.error("【进程链生成】-> 请检查：1) victim的IP提取  2) hostToTraceId映射  3) traceIdToRootNodeMap映射");
        } else {
            log.info("【进程链生成】-> ✅ 桥接边创建完成: 发现victim节点={}, 创建虚拟节点={}, 成功创建桥接边={}", 
                    victimCount, virtualNodeCount, bridgedCount);
        }
        
        return new BridgeResult(virtualNodes, bridgeEdges);
    }
    
    /**
     * 创建虚拟节点
     * 
     * @param victimNodeId victim 节点的 nodeId
     * @param victimIp victim 的 IP 地址
     * @return 虚拟节点
     */
    private ProcessNode createVirtualNode(String victimNodeId, String victimIp) {
        ProcessNode virtualNode = new ProcessNode();
        
        // 设置 nodeId：VIRTUAL_BRIDGE_{victimNodeId}
        String virtualNodeId = "VIRTUAL_BRIDGE_" + victimNodeId;
        virtualNode.setNodeId(virtualNodeId);
        
        // 设置 logType 为 "virtual"（不需要在 NodeType 枚举中添加）
        virtualNode.setLogType("virtual");
        
        // 设置 isChainNode 为 true（作为进程链节点）
        virtualNode.setIsChainNode(true);
        
        // 设置威胁等级为 null（或可以设置为 UNKNOWN）
        virtualNode.setNodeThreatSeverity(null);
        
        // 创建 ChainNode（内容不填充，只设置基本属性）
        ChainNode chainNode = new ChainNode();
        chainNode.setIsRoot(false);
        chainNode.setIsBroken(false);
        chainNode.setIsAlarm(false);
        chainNode.setIsExtensionNode(false);
        chainNode.setExtensionDepth(null);
        // processEntity、entity、alarmNodeInfo 都不设置（保持为 null）
        
        virtualNode.setChainNode(chainNode);
        virtualNode.setStoryNode(null);
        
        // childrenCount 会在后续统一计算，这里不设置
        
        log.debug("【进程链生成】-> 创建虚拟节点: nodeId={}, victimNodeId={}, victimIp={}", 
                virtualNodeId, victimNodeId, victimIp);
        
        return virtualNode;
    }
    
    /**
     * 从 StoryNode 中提取 IP 地址
     * 统一从 storyNode.other.ip 获取（无论 nodeId 是什么）
     */
    private String extractIpFromStoryNode(StoryNode storyNode) {
        if (storyNode == null || storyNode.getNode() == null) {
            return null;
        }
        
        Object ipObj = storyNode.getNode().get("ip");
        if (ipObj != null) {
            String ip = ipObj.toString().trim();
            log.debug("【进程链生成】-> 从 storyNode.other.ip 提取IP: {}", ip);
            return ip;
        }
        
                return null;
    }
}

