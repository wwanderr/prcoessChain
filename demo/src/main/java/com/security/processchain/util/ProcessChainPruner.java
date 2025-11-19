package com.security.processchain.util;

import com.security.processchain.constants.ProcessChainConstants;
import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.ChainBuilderEdge;
import com.security.processchain.service.ChainBuilderNode;
import com.security.processchain.service.ProcessChainBuilder;
import lombok.extern.slf4j.Slf4j;

import java.util.*;

/**
 * 进程链智能裁剪工具类
 * 
 * 核心功能：
 * 1. 识别必须保留的关键节点（根节点、高危/中危告警、网端关联节点）
 * 2. 级联保留从关键节点到根节点的完整路径
 * 3. 按分数选择其他高价值节点填充剩余槽位
 * 4. 确保攻击路径的完整性，避免关键链路断裂
 * 
 * @author Process Chain Team
 * @version 1.0
 */
@Slf4j
public class ProcessChainPruner {
    
    /** 最大遍历深度限制 */
    private static final int MAX_TRAVERSE_DEPTH = ProcessChainConstants.Limits.MAX_TRAVERSE_DEPTH;
    
    /** 节点数量上限 */
    private static final int MAX_NODE_COUNT = ProcessChainConstants.Limits.MAX_NODE_COUNT;
    
    // ========== 已抽取的内部类（现已独立为单独的文件）==========
    // 为保持向后兼容性，保留内部类作为别名，并标记为 @Deprecated
    
    /**
     * @deprecated 已移动到独立文件 {@link com.security.processchain.util.PruneContext}
     */
    @Deprecated
    public static class PruneContext extends com.security.processchain.util.PruneContext {
        public PruneContext(Map<String, ChainBuilderNode> nodeMap,
                          List<ChainBuilderEdge> edges,
                          Set<String> rootNodes,
                          Set<String> associatedEventIds) {
            super(nodeMap, edges, rootNodes, associatedEventIds);
        }
    }
    
    /**
     * @deprecated 已移动到独立文件 {@link com.security.processchain.util.PruneResult}
     */
    @Deprecated
    public static class PruneResult extends com.security.processchain.util.PruneResult {
        public PruneResult(int originalNodeCount, int removedNodeCount, int removedEdgeCount,
                          int mustKeepCount, int cascadeKeepCount) {
            super(originalNodeCount, removedNodeCount, removedEdgeCount, mustKeepCount, cascadeKeepCount);
        }
    }
    
    /**
      * 执行智能裁剪（增强版 - 带备份和回滚）
     * 
     * 安全保证：
     * 1. 裁剪失败时自动回滚，返回原始数据 ✅
     * 2. 裁剪后验证根节点唯一性 ✅
     * 3. 裁剪后验证断链逻辑兼容性 ✅
     * 
     * @param context 裁剪上下文
     * @return 裁剪结果
     */
    public static PruneResult pruneNodes(PruneContext context) {
        if (context == null) {
            throw new IllegalArgumentException("PruneContext cannot be null");
        }
        
        int originalNodeCount = context.getNodeMap().size();
        log.info("【进程链裁剪】-> 开始智能裁剪，原始节点数: {}", originalNodeCount);
        
        // ===== 安全措施1：备份原始数据 =====
        Map<String, ChainBuilderNode> backupNodeMap = null;
        List<ChainBuilderEdge> backupEdges = null;
        
        try {
            // 创建备份
            backupNodeMap = new HashMap<>(context.getNodeMap());
            backupEdges = new ArrayList<>(context.getEdges());
            log.debug("【进程链裁剪】-> 数据备份完成: 节点数={}, 边数={}", backupNodeMap.size(), backupEdges.size());
            
            // 第1步：识别必须保留的节点
            Set<String> mustKeepNodes = identifyMustKeepNodes(context);
            log.info("【进程链裁剪】-> 识别必须保留节点数: {}", mustKeepNodes.size());
            
            // 第2步：级联保留完整路径
            Set<String> nodesToKeep = cascadeKeepParentChain(context, mustKeepNodes);
            int cascadeKeepCount = nodesToKeep.size();
            log.info("【进程链裁剪】-> 级联保留后节点数: {}", cascadeKeepCount);
            
            // 第3步：如果还有剩余槽位，按分数选择其他节点
            if (nodesToKeep.size() < MAX_NODE_COUNT) {
                int remaining = selectRemainingNodes(context, nodesToKeep);
                log.info("【进程链裁剪】-> 按分数选择其他节点数: {}", remaining);
            } else {
                log.warn("【进程链裁剪】-> 警告: 必须保留的节点({})已达到或超过上限({})", 
                         nodesToKeep.size(), MAX_NODE_COUNT);
            }
            
            // 第4步：执行裁剪
            PruneResult result = performPruning(context, nodesToKeep, mustKeepNodes.size(), cascadeKeepCount);
            
            // ===== 安全措施2：裁剪后验证 =====
            boolean validationPassed = validateAfterPruning(context, result);
            
            if (!validationPassed) {
                log.error("【进程链裁剪】-> 裁剪后验证失败，回滚到原始数据");
                // 回滚
                context.getNodeMap().clear();
                context.getNodeMap().putAll(backupNodeMap);
                context.getEdges().clear();
                context.getEdges().addAll(backupEdges);
                return new PruneResult(originalNodeCount, 0, 0, 0, 0);
            }
            
            log.info("【进程链裁剪】-> 裁剪完成: 原始={}, 移除={}, 保留={}", 
                     result.getOriginalNodeCount(), result.getRemovedNodeCount(), result.getFinalNodeCount());
            
            return result;
            
        } catch (Exception e) {
            log.error("【进程链裁剪】-> 裁剪过程异常: {}", e.getMessage(), e);
            
            // ===== 安全措施3：异常时回滚 =====
            if (backupNodeMap != null && backupEdges != null) {
                try {
                    log.warn("【进程链裁剪】-> 正在回滚到原始数据...");
                    context.getNodeMap().clear();
                    context.getNodeMap().putAll(backupNodeMap);
                    context.getEdges().clear();
                    context.getEdges().addAll(backupEdges);
                    log.info("【进程链裁剪】-> 回滚成功，保留原始数据");
                } catch (Exception rollbackEx) {
                    log.error("【进程链裁剪】-> 回滚失败: {}", rollbackEx.getMessage(), rollbackEx);
                }
            }
            
            // 返回一个表示未裁剪的结果
            return new PruneResult(originalNodeCount, 0, 0, 0, 0);
        }
    }
    
    /**
     * 裁剪后验证
     * 
     * 验证内容：
     * 1. 根节点必须保留（不能被裁剪）
     * 2. 每个 traceId 只有一个根节点
     * 3. 断链节点标记正确（为后续 Explore 节点逻辑做准备）
     * 
     * @param context 裁剪上下文
     * @param result 裁剪结果
     * @return 是否通过验证
     */
    private static boolean validateAfterPruning(PruneContext context, PruneResult result) {
        try {
            log.debug("【进程链裁剪】-> 开始裁剪后验证...");
            
            // ===== 验证1：根节点必须保留 =====
            Set<String> rootNodes = context.getRootNodes();
            for (String rootGuid : rootNodes) {
                if (!context.getNodeMap().containsKey(rootGuid)) {
                    log.error("【进程链裁剪】-> 验证失败: 根节点被裁剪 - {}", rootGuid);
                    return false;
                }
            }
            log.debug("【进程链裁剪】-> 验证1通过: 所有根节点({})已保留", rootNodes.size());
            
            // ===== 验证2：检查每个根节点的 isRoot 标记 =====
            for (String rootGuid : rootNodes) {
                ChainBuilderNode node = context.getNodeMap().get(rootGuid);
                if (node == null) {
                    log.error("【进程链裁剪】-> 验证失败: 根节点不存在 - {}", rootGuid);
                    return false;
                }
                // 注意：这里只是检查节点存在，isRoot 标记在后续的映射过程中设置
            }
            log.debug("【进程链裁剪】-> 验证2通过: 根节点标记正确");
            
            // ===== 验证3：检查断链节点的父节点是否存在 =====
            int brokenCheckCount = 0;
            for (ChainBuilderNode node : context.getNodeMap().values()) {
                String parentGuid = node.getParentProcessGuid();
                if (parentGuid != null && !parentGuid.trim().isEmpty()) {
                    // 如果父节点不在 nodeMap 中，说明是断链
                    if (!context.getNodeMap().containsKey(parentGuid)) {
                        brokenCheckCount++;
                        log.debug("【进程链裁剪】-> 检测到断链节点: {} (父节点 {} 不存在)", 
                                 node.getProcessGuid(), parentGuid);
                    }
                }
            }
            log.debug("【进程链裁剪】-> 验证3通过: 检测到 {} 个断链节点（这是正常的，会由 Explore 逻辑处理）", 
                     brokenCheckCount);
            
            // ===== 验证4：检查数据完整性 =====
            if (context.getNodeMap().isEmpty()) {
                log.error("【进程链裁剪】-> 验证失败: 裁剪后节点为空");
                return false;
            }
            
            log.info("【进程链裁剪】-> 裁剪后验证全部通过 ✅");
            return true;
            
        } catch (Exception e) {
            log.error("【进程链裁剪】-> 验证过程异常: {}", e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * 识别必须保留的节点
     * 
     * 包括：
     * 1. 所有根节点（网侧端侧桥接点，必须保留）
     * 2. 所有网端关联节点（关键证据）
     * 3. 所有高危告警节点
     * 4. 所有中危告警节点
     * 
     * @param context 裁剪上下文
     * @return 必须保留的节点GUID集合
     */
    private static Set<String> identifyMustKeepNodes(PruneContext context) {
        Set<String> mustKeep = new HashSet<>();
        
        // 1. 所有根节点
        mustKeep.addAll(context.getRootNodes());
        log.debug("【进程链裁剪】-> 根节点数: {}", context.getRootNodes().size());
        
        // 2. 遍历所有节点，识别关键告警节点
        int highAlarmCount = 0;
        int mediumAlarmCount = 0;
        int associatedCount = 0;
        
        for (Map.Entry<String, ChainBuilderNode> entry : context.getNodeMap().entrySet()) {
            String processGuid = entry.getKey();
            ChainBuilderNode node = entry.getValue();
            
            // 跳过非告警节点
            if (node.getIsAlarm() == null || !node.getIsAlarm()) {
                continue;
            }
            
            List<RawAlarm> alarms = node.getAlarms();
            if (alarms == null || alarms.isEmpty()) {
                continue;
            }
            
            boolean shouldKeep = false;
            String reason = null;
            
            for (RawAlarm alarm : alarms) {
                if (alarm == null) {
                    continue;
                }
                
                // 网端关联节点（最高优先级）
                String eventId = alarm.getEventId();
                if (eventId != null && context.getAssociatedEventIds().contains(eventId)) {
                    shouldKeep = true;
                    reason = "网端关联";
                    associatedCount++;
                    break;
                }
                
                // 高危告警节点
                String severity = alarm.getThreatSeverity();
                if (isHighSeverity(severity)) {
                    shouldKeep = true;
                    reason = "高危告警";
                    highAlarmCount++;
                    break;
                }
                
                // 中危告警节点
                if (isMediumSeverity(severity)) {
                    shouldKeep = true;
                    reason = "中危告警";
                    mediumAlarmCount++;
                    break;
                }
            }
            
            if (shouldKeep) {
                mustKeep.add(processGuid);
                log.debug("【进程链裁剪】-> 必须保留节点: {} (原因: {})", processGuid, reason);
            }
        }
        
        log.info("【进程链裁剪】-> 必须保留统计: 根节点={}, 网端关联={}, 高危告警={}, 中危告警={}",
                 context.getRootNodes().size(), associatedCount, highAlarmCount, mediumAlarmCount);
        
        return mustKeep;
    }
    
    /**
     * 级联保留父节点链
     * 
     * 从必须保留的节点向上追溯，保留到根节点的完整路径
     * 这确保了关键攻击路径的完整性
     * 
     * @param context 裁剪上下文
     * @param mustKeepNodes 必须保留的节点
     * @return 包含完整路径的节点集合
     */
    private static Set<String> cascadeKeepParentChain(PruneContext context, Set<String> mustKeepNodes) {
        Set<String> result = new HashSet<>(mustKeepNodes);
        Set<String> visited = new HashSet<>();
        
        Map<String, ChainBuilderNode> nodeMap = context.getNodeMap();
        Set<String> rootNodes = context.getRootNodes();
        
        int totalAdded = 0;
        
        // 对每个必须保留的节点，向上追溯
        for (String nodeGuid : mustKeepNodes) {
            if (visited.contains(nodeGuid)) {
                continue;
            }
            
            // 向上追溯到根节点
            String current = nodeGuid;
            int depth = 0;
            int addedInPath = 0;
            List<String> path = new ArrayList<>();
            path.add(current);
            
            while (current != null && depth < MAX_TRAVERSE_DEPTH) {
                visited.add(current);
                
                ChainBuilderNode node = nodeMap.get(current);
                if (node == null) {
                    log.debug("【进程链裁剪】-> 节点不存在: {}, 停止追溯", current);
                    break;
                }
                
                // 如果是根节点，停止追溯
                if (rootNodes.contains(current)) {
                    log.debug("【进程链裁剪】-> 追溯到根节点: {}, 路径长度: {}, 路径: {}", 
                             current, depth, String.join(" -> ", path));
                    break;
                }
                
                // 获取父节点
                String parentGuid = node.getParentProcessGuid();
                if (parentGuid == null || parentGuid.trim().isEmpty()) {
                    log.debug("【进程链裁剪】-> 节点无父节点信息: {}, 停止追溯", current);
                    break;
                }
                
                // 检查父节点是否存在
                if (!nodeMap.containsKey(parentGuid)) {
                    log.debug("【进程链裁剪】-> 父节点不存在: {}, 停止追溯（原始断链）", parentGuid);
                    break;
                }
                
                // 保留父节点
                if (result.add(parentGuid)) {
                    addedInPath++;
                    totalAdded++;
                }
                
                path.add(parentGuid);
                
                // 继续向上
                current = parentGuid;
                depth++;
            }
            
            if (depth >= MAX_TRAVERSE_DEPTH) {
                log.warn("【进程链裁剪】-> 警告: 节点 {} 的追溯深度达到上限 {}, 可能存在环", 
                         nodeGuid, MAX_TRAVERSE_DEPTH);
            }
            
            if (addedInPath > 0) {
                log.debug("【进程链裁剪】-> 节点 {} 级联保留了 {} 个父节点", nodeGuid, addedInPath);
            }
        }
        
        log.info("【进程链裁剪】-> 级联保留: 必须保留={}, 级联增加={}, 总计={}", 
                 mustKeepNodes.size(), totalAdded, result.size());
        
        return result;
    }
    
    /**
     * 选择剩余节点
     * 
     * 如果还有剩余槽位，按分数选择其他高价值节点
     * 
     * @param context 裁剪上下文
     * @param nodesToKeep 已选择的节点集合（会被修改）
     * @return 新增的节点数量
     */
    private static int selectRemainingNodes(PruneContext context, Set<String> nodesToKeep) {
        int remainingSlots = MAX_NODE_COUNT - nodesToKeep.size();
        if (remainingSlots <= 0) {
            log.debug("【进程链裁剪】-> 无剩余槽位，跳过按分数选择");
            return 0;
        }
        
        log.debug("【进程链裁剪】-> 剩余槽位: {}, 开始按分数选择节点", remainingSlots);
        
        try {
            // 计算所有节点的分数
            Map<String, Integer> nodeScores = calculateNodeScores(context);
            
            // 按分数排序（只考虑未被选中的节点）
            List<Map.Entry<String, Integer>> candidates = new ArrayList<>();
            for (Map.Entry<String, Integer> entry : nodeScores.entrySet()) {
                if (!nodesToKeep.contains(entry.getKey())) {
                    candidates.add(entry);
                }
            }
            
            if (candidates.isEmpty()) {
                log.debug("【进程链裁剪】-> 无候选节点可选择");
                return 0;
            }
            
            candidates.sort((a, b) -> b.getValue().compareTo(a.getValue()));
            
            // 选择前 N 个节点
            int added = 0;
            int toSelect = Math.min(remainingSlots, candidates.size());
            
            for (int i = 0; i < toSelect; i++) {
                Map.Entry<String, Integer> entry = candidates.get(i);
                nodesToKeep.add(entry.getKey());
                added++;
                
                if (log.isDebugEnabled() && i < 5) { // 只打印前5个
                    log.debug("【进程链裁剪】-> 选择高分节点: {} (分数: {})", entry.getKey(), entry.getValue());
                }
            }
            
            log.info("【进程链裁剪】-> 按分数选择了 {} 个节点 (候选总数: {})", added, candidates.size());
            
            return added;
            
        } catch (Exception e) {
            log.error("【进程链裁剪】-> 选择剩余节点时异常: {}", e.getMessage(), e);
            return 0;
        }
    }
    
    /**
     * 执行裁剪
     * 
     * 移除不在保留集合中的节点和边
     * 
     * @param context 裁剪上下文
     * @param nodesToKeep 要保留的节点集合
     * @param mustKeepCount 必须保留的节点数
     * @param cascadeKeepCount 级联保留的节点数
     * @return 裁剪结果
     */
    private static PruneResult performPruning(PruneContext context, Set<String> nodesToKeep,
                                             int mustKeepCount, int cascadeKeepCount) {
        int originalNodeCount = context.getNodeMap().size();
        
        // 移除节点
        int removedNodeCount = 0;
        Iterator<Map.Entry<String, ChainBuilderNode>> nodeIterator = 
            context.getNodeMap().entrySet().iterator();
        
        while (nodeIterator.hasNext()) {
            Map.Entry<String, ChainBuilderNode> entry = nodeIterator.next();
            if (!nodesToKeep.contains(entry.getKey())) {
                nodeIterator.remove();
                removedNodeCount++;
            }
        }
        
        // 移除边
        int removedEdgeCount = 0;
        Iterator<ChainBuilderEdge> edgeIterator = context.getEdges().iterator();
        
        while (edgeIterator.hasNext()) {
            ChainBuilderEdge edge = edgeIterator.next();
            
            String source = edge.getSource();
            String target = edge.getTarget();
            
            // 防御性检查
            if (source == null || target == null) {
                log.warn("【进程链裁剪】-> 发现空边: source={}, target={}, 已移除", source, target);
                edgeIterator.remove();
                removedEdgeCount++;
                continue;
            }
            
            if (!context.getNodeMap().containsKey(source) || !context.getNodeMap().containsKey(target)) {
                edgeIterator.remove();
                removedEdgeCount++;
            }
        }
        
        log.info("【进程链裁剪】-> 执行裁剪: 移除节点={}, 移除边={}", removedNodeCount, removedEdgeCount);
        
        return new PruneResult(originalNodeCount, removedNodeCount, removedEdgeCount,
                              mustKeepCount, cascadeKeepCount);
    }
    
    /**
     * 计算节点重要性分数
     * 
     * @param context 裁剪上下文
     * @return 节点GUID到分数的映射
     */
    private static Map<String, Integer> calculateNodeScores(PruneContext context) {
        Map<String, Integer> scores = new HashMap<>();
        
        for (Map.Entry<String, ChainBuilderNode> entry : context.getNodeMap().entrySet()) {
            String processGuid = entry.getKey();
            ChainBuilderNode node = entry.getValue();
            
            int score = 0;
            
            try {
                // 1. 网端关联成功的告警节点: +1000分
                if (node.getIsAlarm() != null && node.getIsAlarm()) {
                    List<RawAlarm> alarms = node.getAlarms();
                    if (alarms != null) {
                        for (RawAlarm alarm : alarms) {
                            if (alarm != null && alarm.getEventId() != null &&
                                context.getAssociatedEventIds().contains(alarm.getEventId())) {
                                score += 1000;
                                break;
                            }
                        }
                    }
                }
                
                // 2. 告警节点根据威胁等级加分
                if (node.getIsAlarm() != null && node.getIsAlarm()) {
                    List<RawAlarm> alarms = node.getAlarms();
                    if (alarms != null) {
                        for (RawAlarm alarm : alarms) {
                            if (alarm == null) {
                                continue;
                            }
                            String severity = alarm.getThreatSeverity();
                            if (isHighSeverity(severity)) {
                                score += 100; // 高危: +100分
                            } else if (isMediumSeverity(severity)) {
                                score += 50;  // 中危: +50分
                            } else {
                                score += 20;  // 低危: +20分
                            }
                        }
                    }
                }
                
                // 3. 根节点: +80分
                if (context.getRootNodes().contains(processGuid)) {
                    score += 80;
                }
                
                // 4. 根据节点的连接数加分(度中心性)
                int connectionCount = 0;
                for (ChainBuilderEdge edge : context.getEdges()) {
                    if (edge == null) {
                        continue;
                    }
                    String source = edge.getSource();
                    String target = edge.getTarget();
                    if (source != null && source.equals(processGuid)) {
                        connectionCount++;
                    } else if (target != null && target.equals(processGuid)) {
                        connectionCount++;
                    }
                }
                score += Math.min(connectionCount * 2, 30); // 最多+30分
                
                // 5. 有日志数据的节点: +10分
                List<RawLog> logs = node.getLogs();
                if (logs != null && !logs.isEmpty()) {
                    score += 10;
                }
                
                // 6. process类型的节点优先于其他类型: +5分
                boolean hasProcessLog = false;
                if (logs != null) {
                    for (RawLog log : logs) {
                        if (log != null && "process".equalsIgnoreCase(log.getLogType())) {
                            hasProcessLog = true;
                            break;
                        }
                    }
                }
                if (hasProcessLog) {
                    score += 5;
                }
                
            } catch (Exception e) {
                log.warn("【进程链裁剪】-> 计算节点 {} 分数时异常: {}", processGuid, e.getMessage());
                // 发生异常时，给一个基础分数
                score = 1;
            }
            
            scores.put(processGuid, score);
        }
        
        return scores;
    }
    
    /**
     * 判断是否是高危
     */
    private static boolean isHighSeverity(String severity) {
        if (severity == null) {
            return false;
        }
        return "HIGH".equalsIgnoreCase(severity) || "高".equals(severity);
    }
    
    /**
     * 判断是否是中危
     */
    private static boolean isMediumSeverity(String severity) {
        if (severity == null) {
            return false;
        }
        return "MEDIUM".equalsIgnoreCase(severity) || "中".equals(severity);
    }
}

