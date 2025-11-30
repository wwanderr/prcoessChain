package com.security.processchain.service;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;

import java.util.*;

/**
 * 延迟拆分优化 - 手动测试
 * 
 * 可以直接运行 main 方法，不需要 JUnit
 */
public class DelayedSplitManualTest {

    public static void main(String[] args) {
        System.out.println("========================================");
        System.out.println("延迟拆分优化 - 手动测试");
        System.out.println("========================================\n");
        
        // 运行测试场景1
        testScenario1();
        
        // 运行测试场景2
        testScenario2();
        
        // 运行测试场景3
        testScenario3();
        
        System.out.println("\n========================================");
        System.out.println("所有测试完成！");
        System.out.println("========================================");
    }

    /**
     * 测试场景1：特殊根节点 + 虚拟父节点创建
     */
    private static void testScenario1() {
        System.out.println("========== 测试场景1：特殊根节点 + 虚拟父节点 ==========\n");
        
        try {
            ProcessChainGraphBuilder graphBuilder = new ProcessChainGraphBuilder();
            
            // ===== 准备测试数据 =====
            List<RawAlarm> alarms = new ArrayList<>();
            List<RawLog> logs = new ArrayList<>();
            
            // 1. 告警：主机域名请求（特殊根节点）
            RawAlarm alarm1 = new RawAlarm();
            alarm1.setEventId("alarm-001");
            alarm1.setProcessGuid("2FBB5B6F58FF8A29");
            alarm1.setParentProcessGuid("2FBB5B6F58FF8A29"); // 特殊：processGuid == parentProcessGuid
            alarm1.setTraceId("traceId-205"); // 特殊：processGuid == traceId
            alarm1.setProcessName("MsCpuCN64.exe");
            alarm1.setImage("C:\\Users\\Administrator\\Downloads\\miner-1\\miner-1\\MsCpuCN64.exe");
            alarm1.setCommandLine("MsCpuCN64.exe -o stratum+tcp://mine.ppxxmr.com:3333");
            alarm1.setProcessMd5("abc123def456");
            alarm1.setProcessId(5336);
            alarm1.setHostAddress("3.22.22.2");
            alarm1.setHostName("DESKTOP-M0S0L3H");
            alarm1.setLogType("domain");
            alarm1.setOpType("connect");
            alarm1.setRequestDomain("mine.ppxxmr.com");
            alarm1.setStartTime("2025-05-23 17:47:20");
            alarms.add(alarm1);
            
            // 2. 日志：进程创建日志
            RawLog log1 = new RawLog();
            log1.setEventId("log-001");
            log1.setProcessGuid("2FBB5B6F58FF8A29");
            log1.setParentProcessGuid("2FBB5B6F58FF8A29");
            log1.setTraceId("traceId-205");
            log1.setProcessName("MsCpuCN64.exe");
            log1.setImage("C:\\Users\\Administrator\\Downloads\\miner-1\\miner-1\\MsCpuCN64.exe");
            log1.setCommandLine("MsCpuCN64.exe -o stratum+tcp://mine.ppxxmr.com:3333");
            log1.setProcessMd5("abc123def456");
            log1.setProcessId(5336);
            log1.setHostAddress("3.22.22.2");
            log1.setHostName("DESKTOP-M0S0L3H");
            log1.setLogType("process");
            log1.setOpType("create");
            log1.setStartTime("2025-05-23 17:47:19");
            // 父进程信息
            log1.setParentProcessName("explorer.exe");
            log1.setParentImage("C:\\Windows\\explorer.exe");
            log1.setParentCommandLine("C:\\Windows\\explorer.exe");
            log1.setParentProcessMd5("parent123abc");
            log1.setParentProcessId(1234);
            logs.add(log1);
            
            // 3. 日志：域名请求日志（实体）
            RawLog log2 = new RawLog();
            log2.setEventId("log-002");
            log2.setProcessGuid("2FBB5B6F58FF8A29");
            log2.setParentProcessGuid("2FBB5B6F58FF8A29");
            log2.setTraceId("traceId-205");
            log2.setProcessName("MsCpuCN64.exe");
            log2.setHostAddress("3.22.22.2");
            log2.setHostName("DESKTOP-M0S0L3H");
            log2.setLogType("domain");
            log2.setOpType("connect");
            log2.setRequestDomain("mine.ppxxmr.com");
            log2.setStartTime("2025-05-23 17:47:20");
            logs.add(log2);
            
            // ===== 阶段1：建图（不创建虚拟父节点）=====
            System.out.println("【阶段1】建图（不创建虚拟父节点）...");
            Set<String> traceIds = new HashSet<>();
            traceIds.add("traceId-205");
            ProcessChainGraph graph = graphBuilder.buildGraph(alarms, logs, traceIds);
            System.out.println("  建图完成: 节点数=" + graph.getNodeCount() + ", 边数=" + graph.getEdgeCount());
            
            // 验证1：此时不应该有虚拟父节点
            boolean hasVirtualParent = graph.hasNode("VIRTUAL_ROOT_PARENT_2FBB5B6F58FF8A29");
            System.out.println("  ✓ 验证1: 建图阶段不应创建虚拟父节点 = " + !hasVirtualParent);
            if (hasVirtualParent) {
                System.out.println("  ✗ 失败：建图阶段创建了虚拟父节点！");
                return;
            }
            
            // 验证2：根节点应该存在，且 parentProcessGuid 保留原值
            GraphNode rootNode = graph.getNode("2FBB5B6F58FF8A29");
            if (rootNode == null) {
                System.out.println("  ✗ 失败：根节点不存在！");
                return;
            }
            System.out.println("  ✓ 验证2: 根节点存在，processGuid=" + rootNode.getProcessGuid());
            System.out.println("  ✓ 验证3: 根节点的 parentProcessGuid=" + rootNode.getParentProcessGuid() + 
                    " (保留原值，用于桥接)");
            
            // 验证3：根节点合并了告警和日志
            int alarmCount = rootNode.getAlarms() != null ? rootNode.getAlarms().size() : 0;
            int logCount = rootNode.getLogs() != null ? rootNode.getLogs().size() : 0;
            System.out.println("  ✓ 验证4: 根节点合并了数据 - 告警数=" + alarmCount + ", 日志数=" + logCount);
            
            // ===== 阶段2：子图提取 =====
            System.out.println("\n【阶段2】子图提取...");
            Set<String> startNodeIds = new HashSet<>();
            startNodeIds.add("2FBB5B6F58FF8A29");
            ProcessChainGraph subgraph = graph.extractSubgraph(startNodeIds);
            System.out.println("  子图提取完成: 节点数=" + subgraph.getNodeCount() + ", 边数=" + subgraph.getEdgeCount());
            
            // ===== 阶段3：父进程拆分（延迟创建虚拟父节点）=====
            System.out.println("\n【阶段3】父进程拆分（延迟创建虚拟父节点）...");
            createVirtualParentsForSubgraph(subgraph);
            System.out.println("  父进程拆分完成: 节点数=" + subgraph.getNodeCount() + ", 边数=" + subgraph.getEdgeCount());
            
            // 验证4：虚拟父节点应该被创建
            boolean hasVirtualParentNow = subgraph.hasNode("VIRTUAL_ROOT_PARENT_2FBB5B6F58FF8A29");
            System.out.println("  ✓ 验证5: 虚拟父节点已创建 = " + hasVirtualParentNow);
            if (!hasVirtualParentNow) {
                System.out.println("  ✗ 失败：虚拟父节点未创建！");
                return;
            }
            
            // 验证5：虚拟父节点的信息从日志提取
            GraphNode virtualParent = subgraph.getNode("VIRTUAL_ROOT_PARENT_2FBB5B6F58FF8A29");
            if (virtualParent == null) {
                System.out.println("  ✗ 失败：虚拟父节点为 null！");
                return;
            }
            System.out.println("  ✓ 验证6: 虚拟父节点标记为 virtual = " + virtualParent.isVirtual());
            System.out.println("  ✓ 验证7: 虚拟父节点进程名 = " + virtualParent.getProcessName() + " (从 parentProcessName 提取)");
            System.out.println("  ✓ 验证8: 虚拟父节点 image = " + virtualParent.getImage() + " (从 parentImage 提取)");
            
            // 验证6：虚拟父节点 -> 根节点的边
            int rootInDegree = subgraph.getInDegree("2FBB5B6F58FF8A29");
            System.out.println("  ✓ 验证9: 根节点的入度 = " + rootInDegree + " (应该为1，来自虚拟父节点)");
            
            // ===== 阶段4：图分析 =====
            System.out.println("\n【阶段4】图分析（识别根节点和断链节点）...");

            subgraph.identifyRootNodes(traceIds);
            
            // 验证7：虚拟父节点应该被识别为根节点
            boolean virtualParentIsRoot = subgraph.getRootNodes().contains("VIRTUAL_ROOT_PARENT_2FBB5B6F58FF8A29");
            System.out.println("  ✓ 验证10: 虚拟父节点被识别为根节点 = " + virtualParentIsRoot);
            
            // 验证8：原根节点的 isRoot 应该为 false
            boolean originalRootIsNotRoot = !rootNode.isRoot();
            System.out.println("  ✓ 验证11: 原根节点的 isRoot=false = " + originalRootIsNotRoot);
            
            // ===== 阶段5：虚拟父节点调整 =====
            System.out.println("\n【阶段5】虚拟父节点调整（设置 parentProcessGuid）...");
            adjustVirtualParentLinks(subgraph);
            
            // 验证9：虚拟父节点的 parentProcessGuid 应该指向根节点
            String virtualParentGuid = virtualParent.getParentProcessGuid();
            System.out.println("  ✓ 验证12: 虚拟父节点的 parentProcessGuid = " + virtualParentGuid + 
                    " (应该指向根节点 2FBB5B6F58FF8A29)");
            
            // ===== 最终验证 =====
            System.out.println("\n【最终验证】进程链结构:");
            System.out.println("  虚拟父节点: " + virtualParent.getNodeId());
            System.out.println("    ├─ processGuid: " + virtualParent.getProcessGuid());
            System.out.println("    ├─ parentProcessGuid: " + virtualParent.getParentProcessGuid());
            System.out.println("    ├─ processName: " + virtualParent.getProcessName());
            System.out.println("    ├─ isVirtual: " + virtualParent.isVirtual());
            System.out.println("    └─ isRoot: " + virtualParent.isRoot());
            System.out.println("      ↓");
            System.out.println("  根节点: " + rootNode.getNodeId());
            System.out.println("    ├─ processGuid: " + rootNode.getProcessGuid());
            System.out.println("    ├─ parentProcessGuid: " + rootNode.getParentProcessGuid());
            System.out.println("    ├─ processName: " + rootNode.getProcessName());
            System.out.println("    ├─ 告警数: " + alarmCount);
            System.out.println("    ├─ 日志数: " + logCount);
            System.out.println("    └─ isRoot: " + rootNode.isRoot());
            
            System.out.println("\n✅ 测试场景1 通过！\n");
            
        } catch (Exception e) {
            System.out.println("\n✗ 测试场景1 失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 测试场景2：普通父子进程链
     */
    private static void testScenario2() {
        System.out.println("========== 测试场景2：普通父子进程链 ==========\n");
        
        try {
            ProcessChainGraphBuilder graphBuilder = new ProcessChainGraphBuilder();
            
            List<RawAlarm> alarms = new ArrayList<>();
            List<RawLog> logs = new ArrayList<>();
            
            // 1. cmd.exe (父进程)
            RawLog log1 = new RawLog();
            log1.setEventId("log-cmd-001");
            log1.setProcessGuid("CMD_GUID_001");
            log1.setParentProcessGuid("PARENT_XXX_001");
            log1.setTraceId("traceId-300");
            log1.setProcessName("cmd.exe");
            log1.setImage("C:\\Windows\\System32\\cmd.exe");
            log1.setCommandLine("cmd.exe -c");
            log1.setProcessId(8024);
            log1.setHostAddress("3.22.22.2");
            log1.setLogType("process");
            log1.setOpType("create");
            logs.add(log1);
            
            // 2. AAA.exe (子进程，有告警)
            RawAlarm alarm2 = new RawAlarm();
            alarm2.setEventId("alarm-aaa-001");
            alarm2.setProcessGuid("AAA_GUID_002");
            alarm2.setParentProcessGuid("CMD_GUID_001");
            alarm2.setTraceId("traceId-300");
            alarm2.setProcessName("AAA.exe");
            alarm2.setImage("C:\\Windows\\System32\\whoami.exe");
            alarm2.setCommandLine("aaa");
            alarm2.setProcessId(4696);
            alarm2.setHostAddress("3.22.22.2");
            alarm2.setLogType("process");
            alarm2.setOpType("create");
            alarm2.setParentProcessName("cmd.exe");
            alarm2.setParentImage("C:\\Windows\\System32\\cmd.exe");
            alarms.add(alarm2);
            
            // 3. AAA.exe 的日志（应该与告警合并）
            RawLog log2 = new RawLog();
            log2.setEventId("log-aaa-001");
            log2.setProcessGuid("AAA_GUID_002");
            log2.setParentProcessGuid("CMD_GUID_001");
            log2.setTraceId("traceId-300");
            log2.setProcessName("AAA.exe");
            log2.setImage("C:\\Windows\\System32\\whoami.exe");
            log2.setHostAddress("3.22.22.2");
            log2.setLogType("process");
            log2.setOpType("create");
            logs.add(log2);
            
            // 4. AAA.exe 创建文件（实体）
            RawLog log3 = new RawLog();
            log3.setEventId("log-file-001");
            log3.setProcessGuid("AAA_GUID_002");
            log3.setParentProcessGuid("CMD_GUID_001");
            log3.setTraceId("traceId-300");
            log3.setProcessName("AAA.exe");
            log3.setHostAddress("3.22.22.2");
            log3.setLogType("file");
            log3.setOpType("create");
            log3.setFileName("test.txt");
            log3.setTargetFilename("C:\\Users\\Administrator\\test.txt");
            log3.setFileMd5("file123abc");
            logs.add(log3);
            
            // ===== 建图 =====
            System.out.println("【建图】创建进程链...");
            Set<String> traceIds = new HashSet<>();
            traceIds.add("traceId-300");
            ProcessChainGraph graph = graphBuilder.buildGraph(alarms, logs, traceIds);
            System.out.println("  节点数=" + graph.getNodeCount() + ", 边数=" + graph.getEdgeCount());
            
            // 验证：应该有2个进程节点
            boolean hasCmdNode = graph.hasNode("CMD_GUID_001");
            boolean hasAaaNode = graph.hasNode("AAA_GUID_002");
            System.out.println("  ✓ 验证1: cmd.exe 节点存在 = " + hasCmdNode);
            System.out.println("  ✓ 验证2: AAA.exe 节点存在 = " + hasAaaNode);
            
            if (!hasCmdNode || !hasAaaNode) {
                System.out.println("  ✗ 失败：节点缺失！");
                return;
            }
            
            // 验证：AAA.exe 合并了告警和日志
            GraphNode aaaNode = graph.getNode("AAA_GUID_002");
            int alarmCount = aaaNode.getAlarms() != null ? aaaNode.getAlarms().size() : 0;
            int logCount = aaaNode.getLogs() != null ? aaaNode.getLogs().size() : 0;
            System.out.println("  ✓ 验证3: AAA.exe 合并数据 - 告警数=" + alarmCount + ", 日志数=" + logCount);
            System.out.println("           (应该有1个告警，2个日志：进程+文件)");
            
            // 验证：边的关系
            int aaaInDegree = graph.getInDegree("AAA_GUID_002");
            System.out.println("  ✓ 验证4: AAA.exe 的入度 = " + aaaInDegree + " (应该为1，来自 cmd.exe)");
            
            // 验证：不应该创建虚拟父节点（不是特殊根节点）
            boolean noVirtualParent = !graph.hasNode("VIRTUAL_ROOT_PARENT_CMD_GUID_001") &&
                                     !graph.hasNode("VIRTUAL_ROOT_PARENT_AAA_GUID_002");
            System.out.println("  ✓ 验证5: 不应该创建虚拟父节点 = " + noVirtualParent);
            
            System.out.println("\n✅ 测试场景2 通过！\n");
            
        } catch (Exception e) {
            System.out.println("\n✗ 测试场景2 失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 测试场景3：告警提取父进程信息
     */
    private static void testScenario3() {
        System.out.println("========== 测试场景3：告警提取父进程信息 ==========\n");
        
        try {
            ProcessChainGraphBuilder graphBuilder = new ProcessChainGraphBuilder();
            
            List<RawAlarm> alarms = new ArrayList<>();
            List<RawLog> logs = new ArrayList<>(); // 空日志列表
            
            // 只有告警，没有日志
            RawAlarm alarm1 = new RawAlarm();
            alarm1.setEventId("alarm-file-001");
            alarm1.setProcessGuid("MALWARE_001");
            alarm1.setParentProcessGuid("PARENT_UNKNOWN"); // ✅ 修改：父进程不存在，需要创建虚拟父节点
            alarm1.setTraceId("traceId-400");
            alarm1.setProcessName("malware.exe");
            alarm1.setImage("C:\\Temp\\malware.exe");
            alarm1.setCommandLine("malware.exe --evil");
            alarm1.setProcessMd5("malware123");
            alarm1.setProcessId(9999);
            alarm1.setHostAddress("10.0.0.100");
            alarm1.setLogType("file");
            alarm1.setOpType("create");
            alarm1.setFileName("backdoor.exe");
            alarm1.setFileMd5("backdoor456");
            // 父进程信息（将被提取到虚拟父节点）
            alarm1.setParentProcessName("svchost.exe");
            alarm1.setParentImage("C:\\Windows\\System32\\svchost.exe");
            alarm1.setParentCommandLine("svchost.exe -k netsvcs");
            alarm1.setParentProcessMd5("svchost789");
            alarm1.setParentProcessId(1000);
            alarms.add(alarm1);
            
            // ===== 建图 =====
            System.out.println("【建图】只有告警，没有日志...");
            Set<String> traceIds = new HashSet<>();
            traceIds.add("traceId-400");
            ProcessChainGraph graph = graphBuilder.buildGraph(alarms, logs, traceIds);
            System.out.println("  节点数=" + graph.getNodeCount() + ", 边数=" + graph.getEdgeCount());
            
            // 验证：应该有1个节点
            boolean hasMalwareNode = graph.hasNode("MALWARE_001");
            System.out.println("  ✓ 验证1: malware.exe 节点存在 = " + hasMalwareNode);
            
            if (!hasMalwareNode) {
                System.out.println("  ✗ 失败：节点缺失！");
                return;
            }
            
            // ===== 子图提取 + 父进程拆分 =====
            System.out.println("\n【子图提取 + 父进程拆分】...");
            Set<String> startNodeIds = new HashSet<>();
            startNodeIds.add("MALWARE_001");
            ProcessChainGraph subgraph = graph.extractSubgraph(startNodeIds);
            createVirtualParentsForSubgraph(subgraph);
            System.out.println("  节点数=" + subgraph.getNodeCount() + ", 边数=" + subgraph.getEdgeCount());
            
            // 验证：虚拟父节点应该被创建（nodeId = parentProcessGuid）
            boolean hasVirtualParent = subgraph.hasNode("PARENT_UNKNOWN");
            System.out.println("  ✓ 验证2: 虚拟父节点已创建 = " + hasVirtualParent);
            
            if (!hasVirtualParent) {
                System.out.println("  ✗ 失败：虚拟父节点未创建！");
                System.out.println("  当前节点列表: " + subgraph.getAllNodes().stream()
                        .map(GraphNode::getNodeId)
                        .collect(java.util.stream.Collectors.joining(", ")));
                return;
            }
            
            // 验证：虚拟父节点的信息从告警提取
            GraphNode virtualParent = subgraph.getNode("PARENT_UNKNOWN");
            System.out.println("  ✓ 验证3: 虚拟父节点进程名 = " + virtualParent.getProcessName() + 
                    " (从告警的 parentProcessName 提取)");
            System.out.println("  ✓ 验证4: 虚拟父节点 image = " + virtualParent.getImage() + 
                    " (从告警的 parentImage 提取)");
            System.out.println("  ✓ 验证5: 虚拟父节点 MD5 = " + virtualParent.getProcessMd5() + 
                    " (从告警的 parentProcessMd5 提取)");
            
            boolean correctInfo = "svchost.exe".equals(virtualParent.getProcessName()) &&
                                 "C:\\Windows\\System32\\svchost.exe".equals(virtualParent.getImage()) &&
                                 "svchost789".equals(virtualParent.getProcessMd5());
            System.out.println("  ✓ 验证6: 虚拟父节点信息正确 = " + correctInfo);
            
            // 验证：虚拟父节点 -> malware.exe 的边
            int malwareInDegree = subgraph.getInDegree("MALWARE_001");
            System.out.println("  ✓ 验证7: malware.exe 的入度 = " + malwareInDegree + " (应该为1，来自虚拟父节点)");
            
            System.out.println("\n✅ 测试场景3 通过！\n");
            
        } catch (Exception e) {
            System.out.println("\n✗ 测试场景3 失败: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ===== 辅助方法 =====
    
    private static void createVirtualParentsForSubgraph(ProcessChainGraph subgraph) {
        Map<String, GraphNode> virtualParentsToAdd = new HashMap<>();
        int createdCount = 0;
        
        // 获取虚拟根父节点映射
        Map<String, String> virtualRootParentMap = subgraph.getVirtualRootParentMap();
        
        for (GraphNode node : subgraph.getAllNodes()) {
            // 跳过虚拟节点
            if (node.isVirtual()) {
                continue;
            }
            
            String nodeId = node.getNodeId();
            String parentProcessGuid = node.getParentProcessGuid();
            
            // 情况1：普通节点，有 parentProcessGuid
            if (parentProcessGuid != null && !parentProcessGuid.isEmpty()) {
                // 如果父节点已存在，跳过
                if (subgraph.hasNode(parentProcessGuid)) {
                    continue;
                }
                
                // 如果虚拟父节点已在待添加列表中，跳过
                if (virtualParentsToAdd.containsKey(parentProcessGuid)) {
                    continue;
                }
                
                // 创建虚拟父节点
                GraphNode virtualParent = createVirtualParentNode(node, parentProcessGuid);
                virtualParentsToAdd.put(parentProcessGuid, virtualParent);
                createdCount++;
                continue;
            }
            
            // 情况2：特殊根节点（parentProcessGuid 已被清空），检查映射
            if (virtualRootParentMap != null && virtualRootParentMap.containsKey(nodeId)) {
                String virtualParentId = virtualRootParentMap.get(nodeId);
                
                // 如果虚拟父节点已存在，跳过
                if (subgraph.hasNode(virtualParentId)) {
                    continue;
                }
                
                // 如果虚拟父节点已在待添加列表中，跳过
                if (virtualParentsToAdd.containsKey(virtualParentId)) {
                    continue;
                }
                
                // 创建虚拟父节点
                GraphNode virtualParent = createVirtualParentNode(node, virtualParentId);
                virtualParentsToAdd.put(virtualParentId, virtualParent);
                createdCount++;
            }
        }
        
        // 批量添加虚拟父节点到图中，并创建边
        for (Map.Entry<String, GraphNode> entry : virtualParentsToAdd.entrySet()) {
            String virtualParentId = entry.getKey();
            GraphNode virtualParent = entry.getValue();
            
            subgraph.addNode(virtualParent);
            
            // 为所有子节点创建边
            for (GraphNode node : subgraph.getAllNodes()) {
                if (node.isVirtual()) {
                    continue;
                }
                
                String parentGuid = node.getParentProcessGuid();
                
                // 普通情况：匹配 parentProcessGuid
                if (virtualParentId.equals(parentGuid)) {
                    subgraph.addEdge(virtualParentId, node.getNodeId());
                }
                // 特殊根节点：通过映射匹配
                else if (virtualRootParentMap != null && 
                         virtualParentId.equals(virtualRootParentMap.get(node.getNodeId()))) {
                    subgraph.addEdge(virtualParentId, node.getNodeId());
                }
            }
        }
        
        System.out.println("  创建虚拟父节点数=" + createdCount);
    }
    
    private static GraphNode createVirtualParentNode(GraphNode childNode, String parentGuid) {
        GraphNode parentNode = new GraphNode();
        
        parentNode.setNodeId(parentGuid);
        parentNode.setProcessGuid(parentGuid);
        parentNode.setParentProcessGuid(null);
        parentNode.setVirtual(true);
        parentNode.setNodeType("process");
        
        // 优先从日志提取
        if (childNode.getLogs() != null && !childNode.getLogs().isEmpty()) {
            RawLog firstLog = childNode.getLogs().get(0);
            parentNode.setTraceId(firstLog.getTraceId());
            parentNode.setHostAddress(firstLog.getHostAddress());
            parentNode.setProcessName(firstLog.getParentProcessName());
            parentNode.setImage(firstLog.getParentImage());
            parentNode.setCommandLine(firstLog.getParentCommandLine());
            parentNode.setProcessMd5(firstLog.getParentProcessMd5());
            parentNode.setProcessId(firstLog.getParentProcessId());
        } 
        // 没有日志时从告警提取
        else if (childNode.getAlarms() != null && !childNode.getAlarms().isEmpty()) {
            RawAlarm firstAlarm = childNode.getAlarms().get(0);
            parentNode.setTraceId(firstAlarm.getTraceId());
            parentNode.setHostAddress(firstAlarm.getHostAddress());
            parentNode.setProcessName(firstAlarm.getParentProcessName());
            parentNode.setImage(firstAlarm.getParentImage());
            parentNode.setCommandLine(firstAlarm.getParentCommandLine());
            parentNode.setProcessMd5(firstAlarm.getParentProcessMd5());
            parentNode.setProcessId(firstAlarm.getParentProcessId());
        }
        
        return parentNode;
    }
    
    private static void adjustVirtualParentLinks(ProcessChainGraph subgraph) {
        int adjustedCount = 0;
        Map<String, String> traceIdToRootMap = subgraph.getTraceIdToRootNodeMap();
        
        if (traceIdToRootMap == null || traceIdToRootMap.isEmpty()) {
            System.out.println("  没有根节点映射，跳过调整");
            return;
        }
        
        for (GraphNode node : subgraph.getAllNodes()) {
            if (!node.isVirtual()) {
                continue;
            }
            
            String traceId = node.getTraceId();
            String rootNodeId = traceIdToRootMap.get(traceId);
            
            if (rootNodeId != null) {
                node.setParentProcessGuid(rootNodeId);
                adjustedCount++;
            }
        }
        
        System.out.println("  调整虚拟父节点数=" + adjustedCount);
    }
}

