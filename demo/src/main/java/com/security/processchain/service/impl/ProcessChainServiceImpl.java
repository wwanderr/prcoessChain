package com.security.processchain.service.impl;

import com.security.processchain.constants.ProcessChainConstants;
import com.security.processchain.model.IpMappingRelation;
import com.security.processchain.model.ProcessEdge;
import com.security.processchain.model.ProcessNode;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.*;
import com.security.processchain.util.AlarmElectionUtil;
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
     * 
     * @param ipMappingRelation IP映射关系数据结构
     * @return 合并后的进程链
     */
    public IncidentProcessChain generateProcessChains(IpMappingRelation ipMappingRelation) {
        if (ipMappingRelation == null || ipMappingRelation.getIpAndAssociation() == null 
                || ipMappingRelation.getIpAndAssociation().isEmpty()) {
            log.error("【进程链生成】-> 错误: IP映射关系为空");
            return null;
        }

        List<String> ips = ipMappingRelation.getAllIps();
        
        // 收集所有告警和日志
        List<RawAlarm> allSelectedAlarms = new ArrayList<>();
        List<RawLog> allLogs = new ArrayList<>();

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

            // 使用收集的所有告警和日志构建进程链（直接构建最终模型）
            ProcessChainBuilder builder = new ProcessChainBuilder();
            IncidentProcessChain incidentChain = builder.buildIncidentChain(
                    allSelectedAlarms, allLogs, firstTraceId, null,
                    IncidentConverters.NODE_MAPPER, IncidentConverters.EDGE_MAPPER);
            
            long totalTime = System.currentTimeMillis() - startTime;
            log.info("【进程链生成】-> ========================================");
            log.info("【进程链生成】-> 批量生成完成");
            log.info("【进程链生成】-> 总耗时: {}ms", totalTime);
            log.info("【进程链生成】-> 成功: {}, 失败: {}, 网端关联: {}", successCount, failureCount, associatedCount);
            log.info("【进程链生成】-> 节点数: {}, 边数: {}", 
                    incidentChain.getNodes() != null ? incidentChain.getNodes().size() : 0,
                    incidentChain.getEdges() != null ? incidentChain.getEdges().size() : 0);
            log.info("【进程链生成】-> ========================================");

            return incidentChain;

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
            log.error("生成进程链失败: {}", e.getMessage(), e);
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
            log.warn("告警列表为空");
            return new ArrayList<>();
        }

        String selectedTraceId = null;

        // 场景1: 有网端关联，优先选择关联的告警对应的traceId
        if (hasAssociation && associatedEventId != null && !associatedEventId.trim().isEmpty()) {
            for (RawAlarm alarm : alarms) {
                if (associatedEventId.equals(alarm.getEventId())) {
                    selectedTraceId = alarm.getTraceId();
                    log.info("网端关联成功，选择告警 eventId={}, traceId={}", associatedEventId, selectedTraceId);
                    break;
                }
            }
            
            if (selectedTraceId == null) {
                log.warn("未找到网端关联告警 [eventId={}]，降级使用选举算法", associatedEventId);
            }
        }

        // 场景2: 没有网端关联或关联失败，使用选举算法
        if (selectedTraceId == null) {
            // 按traceId分组
            Map<String, List<RawAlarm>> alarmGroups = groupAlarmsByTraceId(alarms);

            // 使用选举算法选择最佳traceId
            selectedTraceId = AlarmElectionUtil.electAlarm(alarmGroups);
            if (selectedTraceId == null) {
                log.error("告警选举失败");
                return new ArrayList<>();
            }
            
            log.info("选举算法选中 traceId={}", selectedTraceId);
        }

        // 返回选中traceId的所有告警
        List<RawAlarm> selectedAlarms = new ArrayList<>();
        for (RawAlarm alarm : alarms) {
            if (selectedTraceId.equals(alarm.getTraceId())) {
                selectedAlarms.add(alarm);
            }
        }

        log.info("选择了 traceId={} 的 {} 个告警", selectedTraceId, selectedAlarms.size());
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
            log.error("查询告警日志失败: {}", e.getMessage(), e);
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
     * 合并网侧storyNode和端侧chainNode的进程链
     * 
     * @param networkNodes 网侧已生成的节点（包含storyNode）
     * @param networkEdges 网侧已生成的边
     * @param endpointChainResult 端侧生成的进程链结果
     * @return 合并后的完整进程链
     */
    public IncidentProcessChain mergeNetworkAndEndpointChain(
            List<ProcessChainBuilder.ProcessNode> networkNodes,
            List<ProcessChainBuilder.ProcessEdge> networkEdges,
            ProcessChainBuilder.ProcessChainResult endpointChainResult) {
        
        log.info("开始合并网侧和端侧进程链");
        
        if (networkNodes == null && networkEdges == null && endpointChainResult == null) {
            log.warn("所有输入数据均为空");
            return null;
        }
        
        IncidentProcessChain mergedChain = new IncidentProcessChain();
        
        try {
            List<ProcessChainBuilder.ProcessNode> allNodes = new ArrayList<>();
            List<ProcessChainBuilder.ProcessEdge> allEdges = new ArrayList<>();
            
            // 1. 添加网侧节点（storyNode）
            if (networkNodes != null && !networkNodes.isEmpty()) {
                allNodes.addAll(networkNodes);
                log.info("添加网侧节点数: {}", networkNodes.size());
            }
            
            // 2. 添加端侧节点（chainNode）
            if (endpointChainResult != null && endpointChainResult.getNodes() != null) {
                allNodes.addAll(endpointChainResult.getNodes());
                log.info("添加端侧节点数: {}", endpointChainResult.getNodes().size());
            }
            
            // 3. 添加网侧边
            if (networkEdges != null && !networkEdges.isEmpty()) {
                allEdges.addAll(networkEdges);
                log.info("添加网侧边数: {}", networkEdges.size());
            }
            
            // 4. 添加端侧边
            if (endpointChainResult != null && endpointChainResult.getEdges() != null) {
                allEdges.addAll(endpointChainResult.getEdges());
                log.info("添加端侧边数: {}", endpointChainResult.getEdges().size());
            }
            
            // 5. 设置合并后的结果（使用转换器转换为最终模型）
            List<ProcessNode> finalNodes = new ArrayList<>();
            List<ProcessEdge> finalEdges = new ArrayList<>();
            
            for (ProcessChainBuilder.ProcessNode node : allNodes) {
                try {
                    finalNodes.add(IncidentConverters.NODE_MAPPER.toIncidentNode(node));
                } catch (Exception e) {
                    log.error("合并时节点转换失败: processGuid={}, 错误: {}", 
                            node.getProcessGuid(), e.getMessage(), e);
                }
            }
            
            for (ProcessChainBuilder.ProcessEdge edge : allEdges) {
                try {
                    finalEdges.add(IncidentConverters.EDGE_MAPPER.toIncidentEdge(edge));
                } catch (Exception e) {
                    log.error("合并时边转换失败: source={}, target={}, 错误: {}", 
                            edge.getSource(), edge.getTarget(), e.getMessage(), e);
                }
            }
            
            mergedChain.setNodes(finalNodes);
            mergedChain.setEdges(finalEdges);
            
            log.info("进程链合并完成: 总节点数={}, 总边数={}", finalNodes.size(), finalEdges.size());
            
        } catch (Exception e) {
            log.error("合并进程链失败: {}", e.getMessage(), e);
            return null;
        }
        
        return mergedChain;
    }
}

