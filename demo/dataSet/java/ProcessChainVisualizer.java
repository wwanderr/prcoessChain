import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import lombok.Getter;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * 进程链可视化工具
 * 读取IncidentProcessChain的JSON数据，生成链式关系图
 */
public class ProcessChainVisualizer {
    
    // 修改这个路径为你的输入文件路径
    private static final String INPUT_FILE_PATH = "C:\\Users\\18395\\Desktop\\demo\\demo\\dataSet\\output\\test_chain_result.json";
    
    private static final ObjectMapper objectMapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    
    public static void main(String[] args) {
        try {
            System.out.println("开始读取文件: " + INPUT_FILE_PATH);
            
            // 读取JSON文件
            String jsonContent = new String(Files.readAllBytes(Paths.get(INPUT_FILE_PATH)));
            
            // 解析JSON - 首先解析外层包装对象
            DataWrapper wrapper = objectMapper.readValue(jsonContent, DataWrapper.class);
            
            if (wrapper.getData() == null) {
                System.err.println("错误: data 字段为空");
                return;
            }
            
            IncidentProcessChain chain = wrapper.getData();
            
            // 生成可视化图表
            String visualization = generateVisualization(chain);
            
            // 输出到控制台
            System.out.println("\n" + "=".repeat(80));
            System.out.println("进程链关系图");
            System.out.println("=".repeat(80));
            System.out.println(visualization);
            System.out.println("=".repeat(80));
            
            // 保存到文件 - 格式：测试文件名-进程链关系图.md
            Path inputPath = Paths.get(INPUT_FILE_PATH);
            String fileName = inputPath.getFileName().toString();
            String fileNameWithoutExt = fileName.replaceFirst("[.][^.]+$", ""); // 去除扩展名
            String outputFileName = fileNameWithoutExt + "-进程链关系图.md";
            Path outputPath = inputPath.getParent().resolve(outputFileName);
            
            Files.write(outputPath, visualization.getBytes());
            System.out.println("\n可视化结果已保存到: " + outputPath);
            
        } catch (IOException e) {
            System.err.println("读取文件失败: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("处理数据失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 生成可视化图表
     */
    private static String generateVisualization(IncidentProcessChain chain) {
        StringBuilder sb = new StringBuilder();
        
        // 基本信息
        sb.append("\n## 基本信息\n\n");
        sb.append("**TraceID(s)**: ").append(chain.getTraceIds()).append("\n");
        sb.append("**主机IP(s)**: ").append(chain.getHostAddresses()).append("\n");
        sb.append("**威胁等级**: ").append(chain.getThreatSeverity()).append("\n");
        sb.append("**节点数量**: ").append(chain.getNodes() != null ? chain.getNodes().size() : 0).append("\n");
        sb.append("**边数量**: ").append(chain.getEdges() != null ? chain.getEdges().size() : 0).append("\n\n");
        
        // 构建节点映射
        Map<String, ProcessNode> nodeMap = new HashMap<>();
        if (chain.getNodes() != null) {
            for (ProcessNode node : chain.getNodes()) {
                nodeMap.put(node.getNodeId(), node);
            }
        }
        
        // 构建邻接表（父节点 -> 子节点列表）
        Map<String, List<String>> adjacencyList = new HashMap<>();
        Map<String, String> childToParent = new HashMap<>();
        
        if (chain.getEdges() != null) {
            for (ProcessEdge edge : chain.getEdges()) {
                adjacencyList.computeIfAbsent(edge.getSource(), k -> new ArrayList<>()).add(edge.getTarget());
                childToParent.put(edge.getTarget(), edge.getSource());
            }
        }
        
        // 找到根节点 - 优先找告警节点（isRoot=true）
        Set<String> rootNodes = new HashSet<>();
        
        // 首先查找所有告警节点（isRoot=true的进程节点）
        if (chain.getNodes() != null) {
            for (ProcessNode node : chain.getNodes()) {
                if (node.getIsChainNode() != null && node.getIsChainNode() 
                    && node.getChainNode() != null && node.getChainNode().getIsRoot() != null 
                    && node.getChainNode().getIsRoot()) {
                    rootNodes.add(node.getNodeId());
                    System.out.println("DEBUG: 找到告警根节点 = " + node.getNodeId());
                }
            }
        }
        
        // 如果没找到告警节点，才找进程链中没有父节点的节点
        if (rootNodes.isEmpty()) {
            System.out.println("DEBUG: 未找到告警节点，使用进程链顶端节点");
            rootNodes = new HashSet<>(nodeMap.keySet());
            rootNodes.removeAll(childToParent.keySet());
        }
        
        // 生成进程树 - 简洁树形图
        sb.append("## 进程链结构（简洁视图）\n\n");
        sb.append("**图例**: 🌐=网侧攻击 | 💻=端侧进程 | 📄=文件操作 | 🚨=告警节点 | ⚡=ROOT节点\n\n");
        sb.append("```\n");
        
        if (rootNodes.isEmpty()) {
            sb.append("未找到根节点，无法生成进程树\n");
        } else {
            // 找到所有网络节点（作为真正的起点）
            List<ProcessNode> networkNodes = new ArrayList<>();
            for (ProcessNode node : chain.getNodes()) {
                if ("NETWORK".equalsIgnoreCase(node.getLogType())) {
                    networkNodes.add(node);
                }
            }
            
            // 如果有网络节点，从网络节点开始生成树
            if (!networkNodes.isEmpty()) {
                for (ProcessNode networkNode : networkNodes) {
                    generateProcessTree(sb, networkNode.getNodeId(), nodeMap, adjacencyList, "", true, new HashSet<>());
                }
            } else {
                // 没有网络节点，从告警根节点开始
                for (String rootId : rootNodes) {
                    generateProcessTree(sb, rootId, nodeMap, adjacencyList, "", true, new HashSet<>());
                }
            }
        }
        
        sb.append("```\n\n");
        
        // 生成详细的分层结构图 - 支持多个独立攻击链
        sb.append("## 进程链结构（详细视图）\n\n");
        generateDetailedChainViews(sb, chain, nodeMap, adjacencyList, rootNodes);
        
        // 攻击摘要（网络侧信息）
        sb.append("## 攻击摘要\n\n");
        generateAttackSummary(sb, chain);
        sb.append("\n");
        
        // 节点详细信息
        sb.append("## 节点详细信息\n\n");
        if (chain.getNodes() != null) {
            // 分类显示节点
            List<ProcessNode> processNodes = new ArrayList<>();
            List<ProcessNode> networkNodes = new ArrayList<>();
            List<ProcessNode> fileNodes = new ArrayList<>();
            List<ProcessNode> otherNodes = new ArrayList<>();
            
            for (ProcessNode node : chain.getNodes()) {
                if ("NETWORK".equalsIgnoreCase(node.getLogType())) {
                    networkNodes.add(node);
                } else if ("FILE".equalsIgnoreCase(node.getLogType())) {
                    fileNodes.add(node);
                } else if ("PROCESS".equalsIgnoreCase(node.getLogType())) {
                    processNodes.add(node);
                } else {
                    otherNodes.add(node);
                }
            }
            
            // 网络节点信息
            if (!networkNodes.isEmpty()) {
                sb.append("### 🌐 网络侧信息\n\n");
                int idx = 1;
                for (ProcessNode node : networkNodes) {
                    sb.append("#### ").append(idx++).append(". ").append(getNodeDisplayName(node)).append("\n\n");
                    sb.append(formatNodeDetails(node)).append("\n");
                }
            }
            
            // 文件节点信息
            if (!fileNodes.isEmpty()) {
                sb.append("### 📁 文件侧信息\n\n");
                int idx = 1;
                for (ProcessNode node : fileNodes) {
                    sb.append("#### ").append(idx++).append(". ").append(getNodeDisplayName(node)).append("\n\n");
                    sb.append(formatNodeDetails(node)).append("\n");
                }
            }
            
            // 进程节点信息
            if (!processNodes.isEmpty()) {
                sb.append("### ⚙️ 进程链信息\n\n");
                int idx = 1;
                for (ProcessNode node : processNodes) {
                    sb.append("#### ").append(idx++).append(". ").append(getNodeDisplayName(node)).append("\n\n");
                    sb.append(formatNodeDetails(node)).append("\n");
                }
            }
            
            // 其他节点
            if (!otherNodes.isEmpty()) {
                sb.append("### 🔍 其他信息\n\n");
                int idx = 1;
                for (ProcessNode node : otherNodes) {
                    sb.append("#### ").append(idx++).append(". ").append(getNodeDisplayName(node)).append("\n\n");
                    sb.append(formatNodeDetails(node)).append("\n");
                }
            }
        }
        
        // 边关系列表
        sb.append("## 边关系列表\n\n");
        if (chain.getEdges() != null && !chain.getEdges().isEmpty()) {
            sb.append("| 源节点 | 目标节点 | 关系描述 |\n");
            sb.append("|--------|----------|----------|\n");
            for (ProcessEdge edge : chain.getEdges()) {
                String sourceName = getNodeName(nodeMap.get(edge.getSource()));
                String targetName = getNodeName(nodeMap.get(edge.getTarget()));
                String val = edge.getVal() != null ? edge.getVal() : "-";
                sb.append("| ").append(sourceName).append(" | ").append(targetName).append(" | ").append(val).append(" |\n");
            }
        } else {
            sb.append("无边关系\n");
        }
        
        return sb.toString();
    }
    
    /**
     * 递归生成进程树
     */
    private static void generateProcessTree(StringBuilder sb, String nodeId, Map<String, ProcessNode> nodeMap,
                                           Map<String, List<String>> adjacencyList, String prefix, 
                                           boolean isLast, Set<String> visited) {
        // 防止循环引用
        if (visited.contains(nodeId)) {
            return;
        }
        visited.add(nodeId);
        
        ProcessNode node = nodeMap.get(nodeId);
        if (node == null) {
            return;
        }
        
        // 打印当前节点
        String connector = isLast ? "└── " : "├── ";
        sb.append(prefix).append(connector).append(formatNodeForTree(node)).append("\n");
        
        // 获取子节点
        List<String> children = adjacencyList.getOrDefault(nodeId, Collections.emptyList());
        
        // 递归打印子节点
        String newPrefix = prefix + (isLast ? "    " : "│   ");
        for (int i = 0; i < children.size(); i++) {
            boolean isLastChild = (i == children.size() - 1);
            generateProcessTree(sb, children.get(i), nodeMap, adjacencyList, newPrefix, isLastChild, visited);
        }
    }
    
    /**
     * 生成详细的分层结构视图 - 支持多个独立攻击链
     */
    private static void generateDetailedChainViews(StringBuilder sb, IncidentProcessChain chain,
                                                    Map<String, ProcessNode> nodeMap,
                                                    Map<String, List<String>> adjacencyList,
                                                    Set<String> rootNodes) {
        if (chain.getNodes() == null || chain.getNodes().isEmpty()) {
            sb.append("无节点数据\n\n");
            return;
        }
        
        // 找到所有告警节点（根节点）
        List<ProcessNode> alarmNodes = new ArrayList<>();
        for (String nodeId : rootNodes) {
            ProcessNode node = nodeMap.get(nodeId);
            if (node != null && node.getIsChainNode() != null && node.getIsChainNode()) {
                alarmNodes.add(node);
            }
        }
        
        // 找到所有网络节点
        List<ProcessNode> networkNodes = new ArrayList<>();
        for (ProcessNode node : chain.getNodes()) {
            if ("NETWORK".equalsIgnoreCase(node.getLogType())) {
                networkNodes.add(node);
            }
        }
        
        // 构建网络节点到告警节点的映射（通过边关系）
        Map<String, ProcessNode> networkToAlarm = new HashMap<>();
        if (chain.getEdges() != null) {
            for (ProcessEdge edge : chain.getEdges()) {
                // 查找网络节点指向告警节点的边
                ProcessNode sourceNode = nodeMap.get(edge.getSource());
                ProcessNode targetNode = nodeMap.get(edge.getTarget());
                
                if (sourceNode != null && "NETWORK".equalsIgnoreCase(sourceNode.getLogType()) &&
                    targetNode != null && targetNode.getIsChainNode() != null && 
                    targetNode.getIsChainNode() && targetNode.getChainNode() != null &&
                    targetNode.getChainNode().getIsAlarm() != null && 
                    targetNode.getChainNode().getIsAlarm()) {
                    networkToAlarm.put(edge.getSource(), targetNode);
                }
            }
        }
        
        System.out.println("DEBUG: 找到 " + networkNodes.size() + " 个网络节点");
        System.out.println("DEBUG: 找到 " + alarmNodes.size() + " 个告警节点");
        System.out.println("DEBUG: 网络→告警映射: " + networkToAlarm.size() + " 条");
        
        // 如果有多个网络节点，为每个生成独立的攻击链图
        if (networkNodes.size() > 1) {
            sb.append("**检测到 " + networkNodes.size() + " 个独立的网络攻击，将分别展示**\n\n");
            
            int chainIndex = 1;
            for (ProcessNode networkNode : networkNodes) {
                ProcessNode targetAlarm = networkToAlarm.get(networkNode.getNodeId());
                if (targetAlarm != null) {
                    sb.append("### 攻击链 " + chainIndex + "\n\n");
                    generateSingleChainView(sb, chain, nodeMap, targetAlarm, networkNode);
                    chainIndex++;
                }
            }
        } else {
            // 单个攻击链，使用原有逻辑
            ProcessNode rootNode = alarmNodes.isEmpty() ? null : alarmNodes.get(0);
            ProcessNode networkNode = networkNodes.isEmpty() ? null : networkNodes.get(0);
            generateSingleChainView(sb, chain, nodeMap, rootNode, networkNode);
        }
    }
    
    /**
     * 生成单个攻击链的详细视图
     */
    private static void generateSingleChainView(StringBuilder sb, IncidentProcessChain chain,
                                                 Map<String, ProcessNode> nodeMap,
                                                 ProcessNode rootNode,
                                                 ProcessNode networkNode) {
        if (rootNode == null) {
            sb.append("无根节点数据\n\n");
            return;
        }
        
        sb.append("```\n");
        sb.append("════════════════════════════════════════════════════════════════════════════\n");
        sb.append("                            攻 击 链 完 整 视 图                              \n");
        sb.append("════════════════════════════════════════════════════════════════════════════\n\n");
        
        // 使用传入的rootNode
        if (rootNode != null) {
            // 构建从祖先到根节点的完整路径
            List<ProcessNode> chainPath = new ArrayList<>();
            buildChainPath(rootNode.getNodeId(), nodeMap, chainPath, new HashSet<>());
            Collections.reverse(chainPath);
            
            // Debug输出
            System.out.println("\n═══════════ DEBUG: 进程链构建结果 ═══════════");
            System.out.println("根节点: " + rootNode.getNodeId());
            System.out.println("链路中找到 " + chainPath.size() + " 个进程节点:");
            for (int idx = 0; idx < chainPath.size(); idx++) {
                ProcessNode n = chainPath.get(idx);
                if (n.getChainNode() != null && n.getChainNode().getProcessEntity() != null) {
                    ProcessEntity e = n.getChainNode().getProcessEntity();
                    System.out.println("  " + (idx+1) + ". " + e.getProcessName() + 
                                     " (ID:" + n.getNodeId() + ", ParentID:" + e.getParentProcessGuid() + ")");
                }
            }
            System.out.println("════════════════════════════════════════════\n");
            
            // 找到网络节点连接到哪个进程节点（通过边关系）
            String networkTargetNodeId = null;
            if (networkNode != null && chain.getEdges() != null) {
                for (ProcessEdge edge : chain.getEdges()) {
                    if (edge.getSource().equals(networkNode.getNodeId())) {
                        networkTargetNodeId = edge.getTarget();
                        System.out.println("DEBUG: 网络节点 " + networkNode.getNodeId() + " 连接到 " + networkTargetNodeId);
                        break;
                    }
                }
            }
            
            // 显示进程链
            sb.append("【端侧】主机进程执行链\n");
            
            // 遍历进程链，找到告警节点的位置
            int alarmNodeIndex = -1;
            for (int i = 0; i < chainPath.size(); i++) {
                ProcessNode node = chainPath.get(i);
                if (node.getChainNode() != null && node.getChainNode().getIsAlarm() != null && 
                    node.getChainNode().getIsAlarm()) {
                    alarmNodeIndex = i;
                    break;
                }
            }
            
            // 输出完整链路信息
            int processCount = 0;
            for (int i = 0; i < chainPath.size(); i++) {
                ProcessNode node = chainPath.get(i);
                
                if (node.getChainNode() == null || node.getChainNode().getProcessEntity() == null) {
                    continue;
                }
                
                processCount++;
                ProcessEntity entity = node.getChainNode().getProcessEntity();
                boolean isAlarm = node.getChainNode().getIsAlarm() != null && node.getChainNode().getIsAlarm();
                boolean isRoot = node.getChainNode().getIsRoot() != null && node.getChainNode().getIsRoot();
                boolean isExtend = node.getChainNode().getIsExtensionNode() != null && node.getChainNode().getIsExtensionNode();
                
                String icon = isAlarm ? "🚨" : isRoot ? "⚡" : isExtend ? "🔗" : "💻";
                String boxStyle = isAlarm ? "━" : "─";
                
                // 连接线（在第一个节点之前不显示）
                if (processCount > 1) {
                    sb.append("                                 ║\n");
                    sb.append("                                 ▼\n");
                    sb.append("                                 ║\n");
                }
                
                // 在当前节点之前插入网络攻击来源（如果网络节点连接到当前节点）
                if (networkTargetNodeId != null && node.getNodeId().equals(networkTargetNodeId) && 
                    networkNode != null && networkNode.getStoryNode() != null && 
                    networkNode.getStoryNode().getOther() != null) {
                    Map<String, Object> other = networkNode.getStoryNode().getOther();
                    
                    sb.append("    ╔═══════════════════════════════════════════════════════════════════╗\n");
                    sb.append("    ║                    【网侧】网络攻击桥接到端侧                       ║\n");
                    sb.append("    ╠═══════════════════════════════════════════════════════════════════╣\n");
                    sb.append("    ║ 🌐 攻击者: ").append(other.get("srcAddress")).append(":").append(other.get("srcPort")).append("\n");
                    sb.append("    ║    协议: ").append(other.get("protocol")).append(" ").append(other.get("method")).append("\n");
                    sb.append("    ║    目标: ").append(other.get("destAddress")).append(":").append(other.get("destPort")).append("\n");
                    if (other.get("url") != null) {
                        sb.append("    ║    URL: ").append(other.get("url")).append("\n");
                    }
                    if (other.get("ruleName") != null) {
                        sb.append("    ║    检测: ").append(other.get("ruleName")).append("\n");
                    }
                    sb.append("    ╚═══════════════════════════════════════════════════════════════════╝\n");
                    sb.append("                                 ║\n");
                    sb.append("                                 ▼ 桥接到端侧进程\n");
                    sb.append("                                 ║\n");
                    
                    // 只显示一次，设为null避免重复
                    networkNode = null;
                }
                
                // 进程盒子
                sb.append("    ┏").append(boxStyle.repeat(68)).append("┓\n");
                
                // 标题行
                String title = icon + " " + entity.getProcessName() + " (PID:" + entity.getProcessId() + ")";
                if (isAlarm) title += " ⚠️ 告警节点";
                if (isRoot) title += " 🎯 根节点";
                if (isExtend) title += " (扩展节点)";
                sb.append("    ┃ ").append(String.format("%-66s", title)).append(" ┃\n");
                
                // 分隔线
                sb.append("    ┃").append("─".repeat(68)).append("┃\n");
                
                // 用户信息
                String user = entity.getProcessUserName() != null ? entity.getProcessUserName() : "N/A";
                sb.append("    ┃  👤 用户: ").append(String.format("%-55s", user)).append(" ┃\n");
                
                // 命令行
                String cmd = entity.getCommandLine() != null ? entity.getCommandLine() : "";
                if (cmd.length() > 55) {
                    sb.append("    ┃  📝 命令: ").append(cmd.substring(0, 52)).append("... ┃\n");
                } else {
                    sb.append("    ┃  📝 命令: ").append(String.format("%-55s", cmd)).append(" ┃\n");
                }
                
                // 启动时间
                String startTime = entity.getProcessStartTime() != null ? entity.getProcessStartTime() : "N/A";
                sb.append("    ┃  🕐 时间: ").append(String.format("%-55s", startTime)).append(" ┃\n");
                
                // 威胁等级
                String threat = node.getNodeThreatSeverity() != null ? node.getNodeThreatSeverity() : "UNKNOWN";
                String threatIcon = getThreatIcon(threat);
                sb.append("    ┃  ").append(threatIcon).append(" 威胁: ").append(String.format("%-55s", threat)).append(" ┃\n");
                
                // 告警详情
                if (isAlarm && node.getChainNode().getAlarmNodeInfo() != null) {
                    AlarmNodeInfo alarm = node.getChainNode().getAlarmNodeInfo();
                    sb.append("    ┃").append("═".repeat(68)).append("┃\n");
                    sb.append("    ┃  🚨 告警: ").append(String.format("%-55s", alarm.getName())).append(" ┃\n");
                    if (alarm.getRuleType() != null) {
                        sb.append("    ┃     类型: ").append(String.format("%-55s", alarm.getRuleType())).append(" ┃\n");
                    }
                }
                
                sb.append("    ┗").append(boxStyle.repeat(68)).append("┛\n");
            }
            
            // 查找文件节点
            ProcessNode fileNode = null;
            for (ProcessNode node : chain.getNodes()) {
                if ("FILE".equalsIgnoreCase(node.getLogType())) {
                    fileNode = node;
                    break;
                }
            }
            
            // 显示文件操作
            if (fileNode != null && fileNode.getStoryNode() != null && 
                fileNode.getStoryNode().getOther() != null) {
                Map<String, Object> other = fileNode.getStoryNode().getOther();
                
                sb.append("                                 ║\n");
                sb.append("                                 ▼ 创建文件\n");
                sb.append("                                 ║\n");
                sb.append("【端侧】恶意文件\n");
                sb.append("    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n");
                sb.append("    ┃ 📄 文件: ").append(other.get("fileName")).append("\n");
                
                if (other.get("filePath") != null) {
                    String path = other.get("filePath").toString();
                    if (path.length() > 60) {
                        sb.append("    ┃    路径: ").append(path.substring(0, 57)).append("...\n");
                    } else {
                        sb.append("    ┃    路径: ").append(path).append("\n");
                    }
                }
                
                if (other.get("virusName") != null) {
                    sb.append("    ┃    病毒: ").append(other.get("virusName")).append("\n");
                }
                
                if (other.get("fileMd5") != null) {
                    sb.append("    ┃    MD5: ").append(other.get("fileMd5")).append("\n");
                }
                
                String fileThreat = fileNode.getNodeThreatSeverity() != null ? fileNode.getNodeThreatSeverity() : "HIGH";
                sb.append("    ┃    威胁: ").append(fileThreat).append("\n");
                sb.append("    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n");
            }
        }
        
        sb.append("\n════════════════════════════════════════════════════════════════════════════\n");
        sb.append("```\n\n");
    }
    
    /**
     * 获取威胁等级对应的图标
     */
    private static String getThreatIcon(String threat) {
        if (threat == null) return "⚪";
        
        switch (threat.toUpperCase()) {
            case "HIGH":
            case "CRITICAL":
                return "🔴";
            case "MEDIUM":
                return "🟡";
            case "LOW":
                return "🟢";
            default:
                return "⚪";
        }
    }
    
    /**
     * 构建从根节点向上的完整链路（改用迭代方式）
     */
    private static void buildChainPath(String nodeId, Map<String, ProcessNode> nodeMap, 
                                       List<ProcessNode> path, Set<String> visited) {
        String currentNodeId = nodeId;
        
        // 使用循环而不是递归，避免问题
        while (currentNodeId != null && !visited.contains(currentNodeId)) {
            ProcessNode node = nodeMap.get(currentNodeId);
            if (node == null) {
                System.out.println("DEBUG: 找不到节点: " + currentNodeId);
                break;
            }
            
            visited.add(currentNodeId);
            path.add(node);
            
            String processName = "未知";
            if (node.getChainNode() != null && node.getChainNode().getProcessEntity() != null) {
                processName = node.getChainNode().getProcessEntity().getProcessName();
                System.out.println("DEBUG: 添加节点到链路: " + processName + " (ID:" + currentNodeId + ")");
            }
            
            // 查找父节点
            String parentGuid = null;
            if (node.getChainNode() != null && node.getChainNode().getProcessEntity() != null) {
                parentGuid = node.getChainNode().getProcessEntity().getParentProcessGuid();
            }
            
            if (parentGuid != null) {
                System.out.println("DEBUG: 父节点ID: " + parentGuid);
                currentNodeId = parentGuid;
            } else {
                System.out.println("DEBUG: 已到达链路顶端（无父节点）");
                break;
            }
        }
        
        System.out.println("DEBUG: 链路构建完成，共 " + path.size() + " 个节点");
    }
    
    /**
     * 格式化节点用于树形显示
     */
    private static String formatNodeForTree(ProcessNode node) {
        StringBuilder sb = new StringBuilder();
        
        // 使用emoji图标
        String icon = getNodeIcon(node);
        if (icon != null) {
            sb.append(icon).append(" ");
        }
        
        // 节点类型标记
        if (node.getIsChainNode() != null && node.getIsChainNode() && node.getChainNode() != null) {
            ChainNode chainNode = node.getChainNode();
            
            // 标记
            List<String> tags = new ArrayList<>();
            if (chainNode.getIsRoot() != null && chainNode.getIsRoot()) {
                tags.add("ROOT");
            }
            if (chainNode.getIsAlarm() != null && chainNode.getIsAlarm()) {
                tags.add("ALARM");
            }
            if (chainNode.getIsBroken() != null && chainNode.getIsBroken()) {
                tags.add("BROKEN");
            }
            if (chainNode.getIsExtensionNode() != null && chainNode.getIsExtensionNode()) {
                tags.add("EXTEND");
            }
            
            if (!tags.isEmpty()) {
                sb.append("[").append(String.join(",", tags)).append("] ");
            }
            
            // 进程信息
            if (chainNode.getProcessEntity() != null) {
                ProcessEntity entity = chainNode.getProcessEntity();
                sb.append(entity.getProcessName());
                if (entity.getProcessId() != null) {
                    sb.append(" (PID:").append(entity.getProcessId()).append(")");
                }
                if (entity.getProcessUserName() != null) {
                    sb.append(" - ").append(entity.getProcessUserName());
                }
            } else {
                sb.append("进程节点");
            }
            
            // 威胁等级
            if (node.getNodeThreatSeverity() != null) {
                sb.append(" [").append(node.getNodeThreatSeverity()).append("]");
            }
            
        } else if (node.getStoryNode() != null) {
            // 故事线节点（网络、文件等）
            StoryNode storyNode = node.getStoryNode();
            
            if ("NETWORK".equalsIgnoreCase(node.getLogType())) {
                // 网络节点 - 显示详细信息
                Map<String, Object> other = storyNode.getOther();
                if (other != null) {
                    sb.append("[").append(storyNode.getType()).append("] ");
                    sb.append(other.get("srcAddress")).append(":").append(other.get("srcPort"));
                    sb.append(" → ");
                    sb.append(other.get("destAddress")).append(":").append(other.get("destPort"));
                    if (other.get("protocol") != null) {
                        sb.append(" (").append(other.get("protocol")).append(")");
                    }
                } else {
                    sb.append("[").append(storyNode.getType()).append("] 网络连接");
                }
            } else if ("FILE".equalsIgnoreCase(node.getLogType())) {
                // 文件节点
                Map<String, Object> other = storyNode.getOther();
                if (other != null) {
                    sb.append("[").append(storyNode.getType()).append("] ");
                    sb.append(other.get("fileName"));
                    if (other.get("virusName") != null) {
                        sb.append(" (").append(other.get("virusName")).append(")");
                    }
                } else {
                    sb.append("[").append(storyNode.getType()).append("] 文件操作");
                }
            } else {
                sb.append("[").append(storyNode.getType()).append("]");
            }
            
            // 威胁等级
            if (node.getNodeThreatSeverity() != null) {
                sb.append(" [").append(node.getNodeThreatSeverity()).append("]");
            }
        } else {
            sb.append(node.getLogType()).append(" - ").append(node.getNodeId());
        }
        
        return sb.toString();
    }
    
    /**
     * 获取节点图标
     */
    private static String getNodeIcon(ProcessNode node) {
        if (node == null) return null;
        
        // 检查是否是告警节点
        if (node.getIsChainNode() != null && node.getIsChainNode() && 
            node.getChainNode() != null && node.getChainNode().getIsAlarm() != null && 
            node.getChainNode().getIsAlarm()) {
            return "🚨";
        }
        
        // 检查是否是根节点
        if (node.getIsChainNode() != null && node.getIsChainNode() && 
            node.getChainNode() != null && node.getChainNode().getIsRoot() != null && 
            node.getChainNode().getIsRoot()) {
            return "⚡";
        }
        
        // 按类型返回图标
        if ("NETWORK".equalsIgnoreCase(node.getLogType())) {
            return "🌐";
        } else if ("FILE".equalsIgnoreCase(node.getLogType())) {
            return "📄";
        } else if ("PROCESS".equalsIgnoreCase(node.getLogType())) {
            return "💻";
        } else if ("DOMAIN".equalsIgnoreCase(node.getLogType())) {
            return "🌍";
        } else if ("REGISTRY".equalsIgnoreCase(node.getLogType())) {
            return "📝";
        }
        
        return "🔹";
    }
    
    /**
     * 获取节点的网侧/端侧标签
     */
    private static String getSideLabel(ProcessNode node) {
        if (node == null) return null;
        
        // 网络类型节点 = 网侧
        if ("NETWORK".equalsIgnoreCase(node.getLogType())) {
            return "【网侧】";
        }
        
        // 进程、文件、注册表等 = 端侧
        if ("PROCESS".equalsIgnoreCase(node.getLogType()) || 
            "FILE".equalsIgnoreCase(node.getLogType()) ||
            "REGISTRY".equalsIgnoreCase(node.getLogType()) ||
            "DOMAIN".equalsIgnoreCase(node.getLogType())) {
            return "【端侧】";
        }
        
        return null;
    }
    
    /**
     * 生成攻击摘要（提取网络侧和关键信息）
     */
    private static void generateAttackSummary(StringBuilder sb, IncidentProcessChain chain) {
        if (chain.getNodes() == null) return;
        
        // 提取网络信息
        List<ProcessNode> networkNodes = new ArrayList<>();
        List<ProcessNode> alarmNodes = new ArrayList<>();
        
        for (ProcessNode node : chain.getNodes()) {
            if ("NETWORK".equalsIgnoreCase(node.getLogType())) {
                networkNodes.add(node);
            }
            if (node.getIsChainNode() != null && node.getIsChainNode() 
                && node.getChainNode() != null && node.getChainNode().getIsAlarm() != null 
                && node.getChainNode().getIsAlarm()) {
                alarmNodes.add(node);
            }
        }
        
        // 网络攻击信息
        if (!networkNodes.isEmpty()) {
            sb.append("**网络攻击来源**:\n\n");
            for (ProcessNode node : networkNodes) {
                if (node.getStoryNode() != null && node.getStoryNode().getOther() != null) {
                    Map<String, Object> other = node.getStoryNode().getOther();
                    sb.append("- 来源: ").append(other.get("srcAddress")).append(":").append(other.get("srcPort")).append("\n");
                    sb.append("- 目标: ").append(other.get("destAddress")).append(":").append(other.get("destPort")).append("\n");
                    sb.append("- 协议: ").append(other.get("protocol")).append("\n");
                    if (other.get("url") != null) {
                        sb.append("- URL: ").append(other.get("url")).append("\n");
                    }
                    if (other.get("ruleName") != null) {
                        sb.append("- 检测规则: ").append(other.get("ruleName")).append("\n");
                    }
                    sb.append("\n");
                }
            }
        }
        
        // 告警信息摘要
        if (!alarmNodes.isEmpty()) {
            sb.append("**告警事件**:\n\n");
            for (ProcessNode node : alarmNodes) {
                if (node.getChainNode() != null && node.getChainNode().getAlarmNodeInfo() != null) {
                    AlarmNodeInfo alarm = node.getChainNode().getAlarmNodeInfo();
                    sb.append("- ").append(alarm.getName()).append("\n");
                    sb.append("  - 类型: ").append(alarm.getRuleType()).append("\n");
                    if (alarm.getMessage() != null) {
                        sb.append("  - 描述: ").append(alarm.getMessage()).append("\n");
                    }
                }
            }
        }
    }
    
    /**
     * 格式化节点详细信息
     */
    private static String formatNodeDetails(ProcessNode node) {
        StringBuilder sb = new StringBuilder();
        
        sb.append("- **节点ID**: ").append(node.getNodeId()).append("\n");
        sb.append("- **类型**: ").append(node.getLogType()).append("\n");
        sb.append("- **威胁等级**: ").append(node.getNodeThreatSeverity()).append("\n");
        sb.append("- **是否进程链节点**: ").append(node.getIsChainNode()).append("\n");
        
        if (node.getIsChainNode() != null && node.getIsChainNode() && node.getChainNode() != null) {
            ChainNode chainNode = node.getChainNode();
            sb.append("- **是否根节点**: ").append(chainNode.getIsRoot()).append("\n");
            sb.append("- **是否告警节点**: ").append(chainNode.getIsAlarm()).append("\n");
            sb.append("- **是否断链**: ").append(chainNode.getIsBroken()).append("\n");
            
            if (chainNode.getProcessEntity() != null) {
                ProcessEntity entity = chainNode.getProcessEntity();
                sb.append("- **进程名**: ").append(entity.getProcessName()).append("\n");
                sb.append("- **进程ID**: ").append(entity.getProcessId()).append("\n");
                sb.append("- **命令行**: ").append(entity.getCommandLine()).append("\n");
                sb.append("- **用户**: ").append(entity.getProcessUserName()).append("\n");
                sb.append("- **启动时间**: ").append(entity.getProcessStartTime()).append("\n");
                sb.append("- **MD5**: ").append(entity.getProcessMd5()).append("\n");
            }
            
            if (chainNode.getAlarmNodeInfo() != null) {
                AlarmNodeInfo alarmInfo = chainNode.getAlarmNodeInfo();
                sb.append("- **告警名称**: ").append(alarmInfo.getName()).append("\n");
                sb.append("- **告警规则**: ").append(alarmInfo.getRuleName()).append("\n");
                sb.append("- **告警类型**: ").append(alarmInfo.getRuleType()).append("\n");
                if (alarmInfo.getMessage() != null) {
                    sb.append("- **告警消息**: ").append(alarmInfo.getMessage()).append("\n");
                }
            }
        }
        
        // 故事线节点 (网络、文件等)
        if (node.getStoryNode() != null) {
            StoryNode storyNode = node.getStoryNode();
            sb.append("- **故事线类型**: ").append(storyNode.getType()).append("\n");
            
            if (storyNode.getOther() != null && !storyNode.getOther().isEmpty()) {
                sb.append("- **详细信息**:\n");
                for (Map.Entry<String, Object> entry : storyNode.getOther().entrySet()) {
                    sb.append("  - ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
                }
            }
        }
        
        if (node.getChildrenCount() != null) {
            sb.append("- **子节点数**: ").append(node.getChildrenCount()).append("\n");
        }
        
        return sb.toString();
    }
    
    /**
     * 获取节点显示名称
     */
    private static String getNodeDisplayName(ProcessNode node) {
        if (node == null) return "未知节点";
        
        if (node.getIsChainNode() != null && node.getIsChainNode() && 
            node.getChainNode() != null && node.getChainNode().getProcessEntity() != null) {
            return node.getChainNode().getProcessEntity().getProcessName();
        }
        
        if (node.getStoryNode() != null) {
            return node.getStoryNode().getType();
        }
        
        return node.getNodeId();
    }
    
    /**
     * 获取节点名称（简短版）
     */
    private static String getNodeName(ProcessNode node) {
        if (node == null) return "null";
        
        if (node.getIsChainNode() != null && node.getIsChainNode() && 
            node.getChainNode() != null && node.getChainNode().getProcessEntity() != null) {
            ProcessEntity entity = node.getChainNode().getProcessEntity();
            return entity.getProcessName() + "(" + entity.getProcessId() + ")";
        }
        
        return node.getNodeId();
    }
    
    // ==================== 数据结构类 ====================
    
    /**
     * 外层数据包装类
     * 用于解析 {data: {IncidentProcessChain}} 格式的JSON
     */
    static class DataWrapper {
        private IncidentProcessChain data;
        
        public IncidentProcessChain getData() { return data; }
        public void setData(IncidentProcessChain data) { this.data = data; }
    }
    
    static class IncidentProcessChain {
        private List<String> traceIds;
        private List<String> hostAddresses;
        private List<ProcessNode> nodes;
        private List<ProcessEdge> edges;
        private String threatSeverity;
        
        // Getters and Setters
        public List<String> getTraceIds() { return traceIds; }
        public void setTraceIds(List<String> traceIds) { this.traceIds = traceIds; }
        
        public List<String> getHostAddresses() { return hostAddresses; }
        public void setHostAddresses(List<String> hostAddresses) { this.hostAddresses = hostAddresses; }
        
        public List<ProcessNode> getNodes() { return nodes; }
        public void setNodes(List<ProcessNode> nodes) { this.nodes = nodes; }
        
        public List<ProcessEdge> getEdges() { return edges; }
        public void setEdges(List<ProcessEdge> edges) { this.edges = edges; }
        
        public String getThreatSeverity() { return threatSeverity; }
        public void setThreatSeverity(String threatSeverity) { this.threatSeverity = threatSeverity; }
    }
    
    @Getter
    static class ProcessNode {
        // Getters and Setters
        private String logType;
        private String nodeThreatSeverity;
        private String nodeId;
        private Boolean isChainNode;
        private ChainNode chainNode;
        private StoryNode storyNode;
        private Integer childrenCount;

        public void setLogType(String logType) { this.logType = logType; }

        public void setNodeThreatSeverity(String nodeThreatSeverity) { this.nodeThreatSeverity = nodeThreatSeverity; }

        public void setNodeId(String nodeId) { this.nodeId = nodeId; }

        public void setIsChainNode(Boolean isChainNode) { this.isChainNode = isChainNode; }

        public void setChainNode(ChainNode chainNode) { this.chainNode = chainNode; }

        public void setStoryNode(StoryNode storyNode) { this.storyNode = storyNode; }

        public void setChildrenCount(Integer childrenCount) { this.childrenCount = childrenCount; }
    }
    
    static class ProcessEdge {
        private String source;
        private String target;
        private String val;
        
        // Getters and Setters
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
        
        public String getTarget() { return target; }
        public void setTarget(String target) { this.target = target; }
        
        public String getVal() { return val; }
        public void setVal(String val) { this.val = val; }
    }
    
    static class ChainNode {
        private Boolean isRoot;
        private Boolean isBroken;
        private Boolean isAlarm;
        private Boolean isExtensionNode;
        private Integer extensionDepth;
        private AlarmNodeInfo alarmNodeInfo;
        private ProcessEntity processEntity;
        
        // Getters and Setters
        public Boolean getIsRoot() { return isRoot; }
        public void setIsRoot(Boolean isRoot) { this.isRoot = isRoot; }
        
        public Boolean getIsBroken() { return isBroken; }
        public void setIsBroken(Boolean isBroken) { this.isBroken = isBroken; }
        
        public Boolean getIsAlarm() { return isAlarm; }
        public void setIsAlarm(Boolean isAlarm) { this.isAlarm = isAlarm; }
        
        public Boolean getIsExtensionNode() { return isExtensionNode; }
        public void setIsExtensionNode(Boolean isExtensionNode) { this.isExtensionNode = isExtensionNode; }
        
        public Integer getExtensionDepth() { return extensionDepth; }
        public void setExtensionDepth(Integer extensionDepth) { this.extensionDepth = extensionDepth; }
        
        public AlarmNodeInfo getAlarmNodeInfo() { return alarmNodeInfo; }
        public void setAlarmNodeInfo(AlarmNodeInfo alarmNodeInfo) { this.alarmNodeInfo = alarmNodeInfo; }
        
        public ProcessEntity getProcessEntity() { return processEntity; }
        public void setProcessEntity(ProcessEntity processEntity) { this.processEntity = processEntity; }
    }
    
    static class StoryNode {
        private String type;
        private Map<String, Object> other;
        
        // Getters and Setters
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        
        public Map<String, Object> getOther() { return other; }
        public void setOther(Map<String, Object> other) { this.other = other; }
    }
    
    static class ProcessEntity {
        private String processGuid;
        private String parentProcessGuid;
        private String processName;
        private Integer processId;
        private Integer parentProcessId;
        private String commandLine;
        private String image;
        private String processMd5;
        private String processUserName;
        private String processStartTime;
        private String parentProcessName;
        
        // Getters and Setters
        public String getProcessGuid() { return processGuid; }
        public void setProcessGuid(String processGuid) { this.processGuid = processGuid; }
        
        public String getParentProcessGuid() { return parentProcessGuid; }
        public void setParentProcessGuid(String parentProcessGuid) { this.parentProcessGuid = parentProcessGuid; }
        
        public String getProcessName() { return processName; }
        public void setProcessName(String processName) { this.processName = processName; }
        
        public Integer getProcessId() { return processId; }
        public void setProcessId(Integer processId) { this.processId = processId; }
        
        public Integer getParentProcessId() { return parentProcessId; }
        public void setParentProcessId(Integer parentProcessId) { this.parentProcessId = parentProcessId; }
        
        public String getCommandLine() { return commandLine; }
        public void setCommandLine(String commandLine) { this.commandLine = commandLine; }
        
        public String getImage() { return image; }
        public void setImage(String image) { this.image = image; }
        
        public String getProcessMd5() { return processMd5; }
        public void setProcessMd5(String processMd5) { this.processMd5 = processMd5; }
        
        public String getProcessUserName() { return processUserName; }
        public void setProcessUserName(String processUserName) { this.processUserName = processUserName; }
        
        public String getProcessStartTime() { return processStartTime; }
        public void setProcessStartTime(String processStartTime) { this.processStartTime = processStartTime; }
        
        public String getParentProcessName() { return parentProcessName; }
        public void setParentProcessName(String parentProcessName) { this.parentProcessName = parentProcessName; }
    }
    
    static class AlarmNodeInfo {
        private String name;
        private String ruleName;
        private String ruleType;
        private String message;
        private Integer severity;
        
        // Getters and Setters
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        
        public String getRuleName() { return ruleName; }
        public void setRuleName(String ruleName) { this.ruleName = ruleName; }
        
        public String getRuleType() { return ruleType; }
        public void setRuleType(String ruleType) { this.ruleType = ruleType; }
        
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        
        public Integer getSeverity() { return severity; }
        public void setSeverity(Integer severity) { this.severity = severity; }
    }
}

