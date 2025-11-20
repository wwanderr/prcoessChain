package com.security.processchain;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.service.GraphNode;
import com.security.processchain.service.ProcessChainGraph;
import com.security.processchain.service.ProcessChainGraphBuilder;
import com.security.processchain.util.EntityExtractor;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 晚拆分方案测试 - 验证实体提取功能
 */
@Slf4j
public class LateEntityExtractionTest {
    
    @Test
    public void testEntityExtraction() {
        log.info("========================================");
        log.info("测试：晚拆分方案 - 实体提取");
        log.info("========================================");
        
        // 1. 准备测试数据
        List<RawAlarm> alarms = new ArrayList<>();
        List<RawLog> logs = new ArrayList<>();
        
        String traceId = "TRACE_001";
        String processGuid = "PROC_001";
        
        // 1.1 创建一个告警（file类型）
        RawAlarm alarm = new RawAlarm();
        alarm.setProcessGuid(processGuid);
        alarm.setParentProcessGuid(traceId);
        alarm.setTraceId(traceId);
        alarm.setHostAddress("192.168.1.100");
        alarm.setLogType("file");  // ⚠️ 告警是file类型
        alarm.setProcessName("malware.exe");
        alarms.add(alarm);
        
        // 1.2 创建一个file日志
        RawLog fileLog = new RawLog();
        fileLog.setProcessGuid(processGuid);
        fileLog.setParentProcessGuid(traceId);
        fileLog.setTraceId(traceId);
        fileLog.setHostAddress("192.168.1.100");
        fileLog.setLogType("file");  // file类型日志
        fileLog.setOpType("create");
        fileLog.setProcessName("malware.exe");
        fileLog.setTargetFilename("C:\\Windows\\evil.dll");
        fileLog.setFileMd5("abc123");
        fileLog.setStartTime("2025-11-20 10:00:00");
        logs.add(fileLog);
        
        // 1.3 创建一个domain日志
        RawLog domainLog = new RawLog();
        domainLog.setProcessGuid(processGuid);
        domainLog.setParentProcessGuid(traceId);
        domainLog.setTraceId(traceId);
        domainLog.setHostAddress("192.168.1.100");
        domainLog.setLogType("domain");  // domain类型日志
        domainLog.setOpType("connect");
        domainLog.setProcessName("malware.exe");
        domainLog.setRequestDomain("evil.com");
        domainLog.setStartTime("2025-11-20 10:00:01");
        logs.add(domainLog);
        
        // 1.4 创建一个process日志
        RawLog processLog = new RawLog();
        processLog.setProcessGuid(processGuid);
        processLog.setParentProcessGuid(traceId);
        processLog.setTraceId(traceId);
        processLog.setHostAddress("192.168.1.100");
        processLog.setLogType("process");  // process类型日志
        processLog.setOpType("create");
        processLog.setProcessName("malware.exe");
        processLog.setStartTime("2025-11-20 10:00:02");
        logs.add(processLog);
        
        log.info("【测试数据】告警数={}, 日志数={}", alarms.size(), logs.size());
        log.info("【测试数据】日志类型: file=1, domain=1, process=1");
        
        // 2. 建图（只包含进程节点）
        ProcessChainGraphBuilder graphBuilder = new ProcessChainGraphBuilder();
        ProcessChainGraph graph = graphBuilder.buildGraph(alarms, logs, Set.of(traceId));
        
        log.info("【建图后】节点数={}", graph.getNodeCount());
        
        // 验证：建图后只有进程节点
        assertEquals(2, graph.getNodeCount(), "建图后应该有2个进程节点（根节点+子节点）");
        
        for (GraphNode node : graph.getAllNodes()) {
            log.info("【建图后-节点】id={}, nodeType={}, 日志数={}", 
                    node.getNodeId(), node.getNodeType(), 
                    node.getLogs() != null ? node.getLogs().size() : 0);
            
            if (node.getLogs() != null) {
                for (RawLog rawLog : node.getLogs()) {
                    log.info("    日志: logType={}, opType={}", 
                            rawLog.getLogType(), rawLog.getOpType());
                }
            }
        }
        
        // 验证：所有节点的 nodeType 都是 "process"
        for (GraphNode node : graph.getAllNodes()) {
            assertEquals("process", node.getNodeType(), 
                    "建图后所有节点的nodeType都应该是'process'，但节点" + node.getNodeId() + "是'" + node.getNodeType() + "'");
        }
        
        // 3. 实体提取
        log.info("========================================");
        log.info("开始实体提取...");
        log.info("========================================");
        
        EntityExtractor.extractEntitiesFromGraph(graph);
        
        log.info("【实体提取后】节点总数={}", graph.getNodeCount());
        
        // 验证：实体提取后应该有 2个进程节点 + 2个实体节点 = 4个节点
        assertTrue(graph.getNodeCount() >= 4, 
                "实体提取后应该至少有4个节点（2进程+2实体），实际: " + graph.getNodeCount());
        
        // 统计节点类型
        Map<String, Integer> nodeTypeCounts = new HashMap<>();
        for (GraphNode node : graph.getAllNodes()) {
            String nodeType = node.getNodeType();
            nodeTypeCounts.put(nodeType, nodeTypeCounts.getOrDefault(nodeType, 0) + 1);
            
            log.info("【实体提取后-节点】id={}, nodeType={}", 
                    node.getNodeId(), node.getNodeType());
        }
        
        log.info("【节点类型统计】{}", nodeTypeCounts);
        
        // 验证：应该有实体节点
        assertTrue(nodeTypeCounts.containsKey("file_entity"), "应该有file_entity节点");
        assertTrue(nodeTypeCounts.containsKey("domain_entity"), "应该有domain_entity节点");
        
        // 验证：实体节点的父节点是进程节点
        for (GraphNode node : graph.getAllNodes()) {
            if (node.getNodeType().endsWith("_entity")) {
                List<String> parents = graph.getParents(node.getNodeId());
                assertFalse(parents.isEmpty(), "实体节点应该有父节点");
                
                String parentId = parents.get(0);
                GraphNode parentNode = graph.getNode(parentId);
                assertEquals("process", parentNode.getNodeType(), 
                        "实体节点的父节点应该是进程节点");
                
                log.info("【验证】实体节点 {} 的父节点 {} 是进程节点 ✅", 
                        node.getNodeId(), parentId);
            }
        }
        
        log.info("========================================");
        log.info("✅ 测试通过！实体提取工作正常");
        log.info("========================================");
    }
}

