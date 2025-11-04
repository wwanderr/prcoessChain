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
        
        // 构建节点映射（处理nodeId为null的情况）
        Map<String, ProcessNode> nodeMap = new HashMap<>();
        if (chain.getNodes() != null) {
            int nullNodeIndex = 0;
            for (ProcessNode node : chain.getNodes()) {
                String nodeId = node.getNodeId();
                // 如果nodeId为null，使用type或其他标识符作为临时ID
                if (nodeId == null || nodeId.isEmpty()) {
                    if (node.getStoryNode() != null && node.getStoryNode().getNode() != null) {
                        Map<String, Object> nodeInfo = node.getStoryNode().getNode();
                        String type = (String) nodeInfo.get("type");
                        if (type != null) {
                            nodeId = type;  // 使用type作为ID
                        } else {
                            nodeId = "NULL_NODE_" + (++nullNodeIndex);  // 最后的手段
                        }
                    } else {
                        nodeId = "NULL_NODE_" + (++nullNodeIndex);
                    }
                }
                nodeMap.put(nodeId, node);
                // 如果原始nodeId不是null，也建立一个映射（用于后续查找）
                if (node.getNodeId() != null && !nodeId.equals(node.getNodeId())) {
                    // 已经在上面put了，这里不需要额外处理
                }
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
                // 识别网络节点：logType=NETWORK 或者 storyNode.type=srcNode
                boolean isNetworkNode = "NETWORK".equalsIgnoreCase(node.getLogType());
                if (!isNetworkNode && node.getStoryNode() != null && "srcNode".equals(node.getStoryNode().getType())) {
                    isNetworkNode = true;
                }
                if (isNetworkNode) {
                    networkNodes.add(node);
                }
            }
            
            // 如果有网络节点，从网络节点开始生成树
            if (!networkNodes.isEmpty()) {
                // 找到网络节点中没有父节点的（真正的起点）
                Set<String> networkNodeIds = new HashSet<>();
                for (ProcessNode nn : networkNodes) {
                    networkNodeIds.add(nn.getNodeId());
                }
                
                // 找到网络节点中没有被其他节点指向的（顶层网络节点）
                Set<String> topNetworkNodes = new HashSet<>(networkNodeIds);
                topNetworkNodes.removeAll(childToParent.keySet());
                
                if (!topNetworkNodes.isEmpty()) {
                    for (String topNodeId : topNetworkNodes) {
                        generateProcessTree(sb, topNodeId, nodeMap, adjacencyList, "", true, new HashSet<>());
                    }
                } else {
                    // 如果所有网络节点都有父节点，选择第一个
                    generateProcessTree(sb, networkNodes.get(0).getNodeId(), nodeMap, adjacencyList, "", true, new HashSet<>());
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
        
        // 找到所有网络节点（包括IP节点）
        List<ProcessNode> networkNodes = new ArrayList<>();
        for (ProcessNode node : chain.getNodes()) {
            boolean isNetworkNode = "NETWORK".equalsIgnoreCase(node.getLogType());
            // 也识别 storyNode.type=srcNode 的IP节点
            if (!isNetworkNode && node.getStoryNode() != null && "srcNode".equals(node.getStoryNode().getType())) {
                isNetworkNode = true;
            }
            if (isNetworkNode) {
                networkNodes.add(node);
            }
        }
        
        // 构建网络节点到根节点的映射（通过边关系）
        // 根节点可能是告警节点或者isRoot=true的节点
        Map<String, ProcessNode> networkToRoot = new HashMap<>();
        Set<String> rootNodeIds = new HashSet<>();
        for (String nodeId : rootNodes) {
            rootNodeIds.add(nodeId);
        }
        
        if (chain.getEdges() != null) {
            for (ProcessEdge edge : chain.getEdges()) {
                ProcessNode sourceNode = nodeMap.get(edge.getSource());
                ProcessNode targetNode = nodeMap.get(edge.getTarget());
                
                // 查找网络节点（或IP节点）指向根节点的边
                boolean isNetworkSource = false;
                if (sourceNode != null) {
                    isNetworkSource = "NETWORK".equalsIgnoreCase(sourceNode.getLogType()) ||
                                    (sourceNode.getStoryNode() != null && "srcNode".equals(sourceNode.getStoryNode().getType()));
                }
                
                boolean isRootTarget = targetNode != null && rootNodeIds.contains(targetNode.getNodeId());
                
                if (isNetworkSource && isRootTarget) {
                    // 找到最早的网络源节点（没有父节点的那个）
                    String networkSourceId = edge.getSource();
                    // 回溯找到最顶层的网络节点
                    ProcessNode topNetworkNode = findTopNetworkNode(sourceNode, chain.getEdges(), nodeMap);
                    networkToRoot.put(topNetworkNode.getNodeId(), targetNode);
                    System.out.println("DEBUG: 映射 网络节点 " + topNetworkNode.getNodeId() + " → 根节点 " + targetNode.getNodeId());
                }
            }
        }
        
        System.out.println("DEBUG: 找到 " + networkNodes.size() + " 个网络节点");
        System.out.println("DEBUG: 找到 " + alarmNodes.size() + " 个告警节点");
        System.out.println("DEBUG: 网络→根节点映射: " + networkToRoot.size() + " 条");
        
        // 如果有多个独立的网络链路，为每个生成独立的攻击链图
        if (networkToRoot.size() > 1) {
            sb.append("**检测到 " + networkToRoot.size() + " 个独立的网络攻击链，将分别展示**\n\n");
            
            int chainIndex = 1;
            for (Map.Entry<String, ProcessNode> entry : networkToRoot.entrySet()) {
                ProcessNode topNetworkNode = nodeMap.get(entry.getKey());
                ProcessNode targetRoot = entry.getValue();
                sb.append("### 攻击链 " + chainIndex + "\n\n");
                generateSingleChainView(sb, chain, nodeMap, targetRoot, topNetworkNode);
                chainIndex++;
            }
        } else {
            // 单个攻击链，使用原有逻辑
            ProcessNode rootNode = alarmNodes.isEmpty() ? null : alarmNodes.get(0);
            ProcessNode networkNode = networkNodes.isEmpty() ? null : networkNodes.get(0);
            generateSingleChainView(sb, chain, nodeMap, rootNode, networkNode);
        }
    }
    
    /**
     * 找到最顶层的网络节点（递归向上查找没有父节点的网络节点）
     */
    private static ProcessNode findTopNetworkNode(ProcessNode node, List<ProcessEdge> edges, Map<String, ProcessNode> nodeMap) {
        if (node == null || edges == null) return node;
        
        // 查找指向当前节点的边
        for (ProcessEdge edge : edges) {
            if (edge.getTarget().equals(node.getNodeId())) {
                ProcessNode parentNode = nodeMap.get(edge.getSource());
                if (parentNode != null) {
                    // 检查父节点是否也是网络节点
                    boolean isNetworkNode = "NETWORK".equalsIgnoreCase(parentNode.getLogType()) ||
                                          (parentNode.getStoryNode() != null && "srcNode".equals(parentNode.getStoryNode().getType()));
                    if (isNetworkNode) {
                        // 继续向上查找
                        return findTopNetworkNode(parentNode, edges, nodeMap);
                    }
                }
            }
        }
        
        // 没有网络父节点，当前节点就是顶层网络节点
        return node;
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
        
        // 构建完整的攻击链路径（包括IP节点和进程节点）
        // buildFullChainPath已经按照边关系从上到下（网侧→端侧）的顺序构建，不需要反转
        List<ChainStep> fullChain = buildFullChainPath(rootNode.getNodeId(), nodeMap, chain.getEdges());
        
        // 使用传入的rootNode
        if (rootNode != null) {
            // 构建从祖先到根节点的进程链路径（用于兼容性）
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
            
            // 显示完整攻击链（包括IP节点和进程节点，支持同级分支）
            sb.append("【完整攻击链】\n");
            
            // 重新构建树形结构以支持分支展示
            Map<String, List<String>> parentToChildren = new HashMap<>();
            Map<String, String> edgeDescriptions = new HashMap<>();
            
            // 构建类型标识符到节点ID的映射
            Map<String, String> typeToNodeId = new HashMap<>();
            for (Map.Entry<String, ProcessNode> entry : nodeMap.entrySet()) {
                ProcessNode node = entry.getValue();
                if (node.getStoryNode() != null && node.getStoryNode().getNode() != null) {
                    Map<String, Object> nodeInfo = node.getStoryNode().getNode();
                    String type = (String) nodeInfo.get("type");
                    if (type != null) {
                        typeToNodeId.put(type, entry.getKey());
                    }
                }
            }
            
            if (chain.getEdges() != null) {
                for (ProcessEdge edge : chain.getEdges()) {
                    String sourceId = edge.getSource();
                    String targetId = edge.getTarget();
                    
                    if (!nodeMap.containsKey(sourceId) && typeToNodeId.containsKey(sourceId)) {
                        sourceId = typeToNodeId.get(sourceId);
                    }
                    if (!nodeMap.containsKey(targetId) && typeToNodeId.containsKey(targetId)) {
                        targetId = typeToNodeId.get(targetId);
                    }
                    
                    if (nodeMap.containsKey(sourceId) && nodeMap.containsKey(targetId)) {
                        parentToChildren.computeIfAbsent(sourceId, k -> new ArrayList<>()).add(targetId);
                        edgeDescriptions.put(targetId, edge.getVal() != null ? edge.getVal() : "");
                    }
                }
            }
            
            // 找到起点节点
            Map<String, String> childToParent = new HashMap<>();
            for (Map.Entry<String, List<String>> entry : parentToChildren.entrySet()) {
                for (String child : entry.getValue()) {
                    childToParent.put(child, entry.getKey());
                }
            }
            
            Set<String> startNodes = new HashSet<>();
            for (String nodeId : nodeMap.keySet()) {
                if (!childToParent.containsKey(nodeId) && parentToChildren.containsKey(nodeId)) {
                    startNodes.add(nodeId);
                }
            }
            
            if (startNodes.isEmpty()) {
                startNodes.add(rootNode.getNodeId());
            }
            
            // 从起点节点开始，使用树形结构展示（支持同级分支）
            Set<String> visited = new HashSet<>();
            for (String startNode : startNodes) {
                displayTreeFromNode(sb, startNode, nodeMap, parentToChildren, edgeDescriptions, "    ", true, visited);
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
     * 使用树形结构显示节点（支持同级分支）
     * 策略：当有多个子节点时，先显示所有第一层子节点（同级），再递归显示每个子节点的子树
     * 修复：确保所有子节点都被正确遍历，避免遗漏
     */
    private static void displayTreeFromNode(StringBuilder sb, String nodeId, 
                                             Map<String, ProcessNode> nodeMap,
                                             Map<String, List<String>> parentToChildren,
                                             Map<String, String> edgeDescriptions,
                                             String prefix,
                                             boolean isLast,
                                             Set<String> visited) {
        if (nodeId == null) {
            System.out.println("WARNING: displayTreeFromNode called with null nodeId");
            return;
        }
        
        if (visited.contains(nodeId)) {
            System.out.println("WARNING: 节点 " + nodeId + " 已被访问，跳过（可能存在循环引用）");
            return;
        }
        
        ProcessNode node = nodeMap.get(nodeId);
        if (node == null) {
            System.out.println("WARNING: 找不到节点 " + nodeId);
            return;
        }
        
        visited.add(nodeId);
        System.out.println("DEBUG: 正在显示节点 " + nodeId + " (已访问: " + visited.size() + " 个节点)");
        
        // 获取子节点列表
        List<String> children = parentToChildren.get(nodeId);
        if (children == null || children.isEmpty()) {
            children = new ArrayList<>();
        } else {
            System.out.println("DEBUG: 节点 " + nodeId + " 有 " + children.size() + " 个子节点: " + children);
        }
        
        // 如果有多个子节点，对它们进行排序（优先显示桥接、段链）
        List<String> sortedChildren = new ArrayList<>(children);
        sortedChildren.sort((a, b) -> {
            String descA = edgeDescriptions.get(a);
            String descB = edgeDescriptions.get(b);
            
            boolean isBridgeA = "桥接".equals(descA);
            boolean isBridgeB = "桥接".equals(descB);
            if (isBridgeA && !isBridgeB) return -1;
            if (!isBridgeA && isBridgeB) return 1;
            
            boolean isSegmentA = "段链".equals(descA);
            boolean isSegmentB = "段链".equals(descB);
            if (isSegmentA && !isSegmentB) return -1;
            if (!isSegmentA && isSegmentB) return 1;
            
            return 0;
        });
        
        // 显示当前节点（使用prefix作为缩进）
        displayNodeBox(sb, node, prefix);
        
        // 如果有子节点，显示连接线和子节点
        if (!sortedChildren.isEmpty()) {
            // 连接线（使用基础的37个空格，不加prefix）
            sb.append("                                 ║\n");
            
            // 如果有多个子节点，需要显示分支
            if (sortedChildren.size() > 1) {
                System.out.println("DEBUG: 节点 " + nodeId + " 有多个子节点，显示分支结构");
                // 对于多个分支，每个分支完整显示（连接线 + 节点 + 子树）
                for (int i = 0; i < sortedChildren.size(); i++) {
                    String childId = sortedChildren.get(i);
                    boolean isLastChild = (i == sortedChildren.size() - 1);
                    String edgeDesc = edgeDescriptions.get(childId);
                    
                    System.out.println("DEBUG: 显示分支 " + (i+1) + "/" + sortedChildren.size() + ": " + childId + " (边描述: " + edgeDesc + ")");
                    
                    // 分支连接符（使用基础的37个空格）
                    sb.append("                                 ");
                    if (i == 0) {
                        sb.append("├─→");
                    } else if (isLastChild) {
                        sb.append("└─→");
                    } else {
                        sb.append("├─→");
                    }
                    
                    if (edgeDesc != null && !edgeDesc.isEmpty()) {
                        sb.append(" ").append(edgeDesc);
                    }
                    sb.append("\n");
                    
                    // 显示子节点前的连接线
                    String branchIndent = isLastChild ? "    " : "│   ";
                    sb.append("                                 ").append(branchIndent).append("║\n");
                    
                    // 显示子节点本身（缩进为：基础37空格 + 分支缩进）
                    ProcessNode childNode = nodeMap.get(childId);
                    if (childNode != null) {
                        if (!visited.contains(childId)) {
                            visited.add(childId);
                            displayNodeBox(sb, childNode, "                                 " + branchIndent);
                            
                            // **修复关键点：递归显示这个子节点的完整子树**
                            List<String> grandChildren = parentToChildren.get(childId);
                            if (grandChildren != null && !grandChildren.isEmpty()) {
                                System.out.println("DEBUG: 子节点 " + childId + " 还有 " + grandChildren.size() + " 个子节点，继续递归");
                                // 使用递归调用来显示完整子树，而不是手动遍历第一层
                                sb.append("                                 ").append(branchIndent).append("║\n");
                                displayTreeFromNodeRecursive(sb, childId, nodeMap, parentToChildren, 
                                                            edgeDescriptions, "                                 " + branchIndent, 
                                                            visited);
                            }
                        } else {
                            System.out.println("WARNING: 子节点 " + childId + " 已被访问");
                        }
                    } else {
                        System.out.println("WARNING: 找不到子节点 " + childId);
                    }
                }
            } else {
                // 单个子节点：正常显示
                String childId = sortedChildren.get(0);
                String edgeDesc = edgeDescriptions.get(childId);
                
                System.out.println("DEBUG: 显示单个子节点: " + childId + " (边描述: " + edgeDesc + ")");
                
                sb.append("                                 ▼");
                if (edgeDesc != null && !edgeDesc.isEmpty()) {
                    sb.append(" ").append(edgeDesc);
                }
                sb.append("\n");
                sb.append("                                 ║\n");
                
                displayTreeFromNode(sb, childId, nodeMap, parentToChildren, edgeDescriptions, 
                                   prefix, true, visited);
            }
        } else {
            System.out.println("DEBUG: 节点 " + nodeId + " 没有子节点（叶子节点）");
        }
    }
    
    /**
     * 递归显示子树的辅助方法（确保所有层级都被正确显示）
     */
    private static void displayTreeFromNodeRecursive(StringBuilder sb, String nodeId,
                                                     Map<String, ProcessNode> nodeMap,
                                                     Map<String, List<String>> parentToChildren,
                                                     Map<String, String> edgeDescriptions,
                                                     String baseIndent,
                                                     Set<String> visited) {
        List<String> children = parentToChildren.get(nodeId);
        if (children == null || children.isEmpty()) {
            return;
        }
        
        // 排序子节点
        List<String> sortedChildren = new ArrayList<>(children);
        sortedChildren.sort((a, b) -> {
            String descA = edgeDescriptions.get(a);
            String descB = edgeDescriptions.get(b);
            boolean isBridgeA = "桥接".equals(descA);
            boolean isBridgeB = "桥接".equals(descB);
            if (isBridgeA && !isBridgeB) return -1;
            if (!isBridgeA && isBridgeB) return 1;
            boolean isSegmentA = "段链".equals(descA);
            boolean isSegmentB = "段链".equals(descB);
            if (isSegmentA && !isSegmentB) return -1;
            if (!isSegmentA && isSegmentB) return 1;
            return 0;
        });
        
        for (int i = 0; i < sortedChildren.size(); i++) {
            String childId = sortedChildren.get(i);
            boolean isLastChild = (i == sortedChildren.size() - 1);
            
            if (visited.contains(childId)) {
                System.out.println("WARNING: 递归时发现已访问节点 " + childId + "，跳过");
                continue;
            }
            
            String edgeDesc = edgeDescriptions.get(childId);
            System.out.println("DEBUG: 递归显示子节点 " + (i+1) + "/" + sortedChildren.size() + ": " + childId);
            
            // 显示连接符和边描述
            if (sortedChildren.size() == 1) {
                sb.append(baseIndent).append("▼");
            } else {
                sb.append(baseIndent);
                if (i == 0) {
                    sb.append("├─→");
                } else if (isLastChild) {
                    sb.append("└─→");
                } else {
                    sb.append("├─→");
                }
            }
            
            if (edgeDesc != null && !edgeDesc.isEmpty()) {
                sb.append(" ").append(edgeDesc);
            }
            sb.append("\n");
            sb.append(baseIndent).append(sortedChildren.size() == 1 ? "║" : (isLastChild ? "    ║" : "│   ║")).append("\n");
            
            // 显示子节点
            ProcessNode childNode = nodeMap.get(childId);
            if (childNode != null) {
                visited.add(childId);
                String childIndent = baseIndent + (sortedChildren.size() == 1 ? "" : (isLastChild ? "    " : "│   "));
                displayNodeBox(sb, childNode, childIndent);
                
                // 继续递归显示更深层的子节点
                List<String> grandChildren = parentToChildren.get(childId);
                if (grandChildren != null && !grandChildren.isEmpty()) {
                    sb.append(childIndent).append("║\n");
                    displayTreeFromNodeRecursive(sb, childId, nodeMap, parentToChildren, 
                                                edgeDescriptions, childIndent, visited);
                }
            }
        }
    }
    
    /**
     * 显示节点盒子（根据节点类型显示不同样式）
     * @param indent 缩进前缀（用于多分支显示）
     */
    private static void displayNodeBox(StringBuilder sb, ProcessNode node, String indent) {
        if (node == null) return;
        
        // 判断节点类型
        boolean isIPNode = (node.getStoryNode() != null && "srcNode".equals(node.getStoryNode().getType()));
        boolean isNetworkEventNode = "NETWORK".equalsIgnoreCase(node.getLogType());
        boolean isProcessNode = (node.getIsChainNode() != null && node.getIsChainNode());
        boolean isFileNode = "FILE".equalsIgnoreCase(node.getLogType());
        
        if (isIPNode) {
            // 显示IP节点（或网络节点）
            Map<String, Object> nodeInfo = node.getStoryNode().getNode();
            if (nodeInfo != null) {
                String ip = (String) nodeInfo.get("ip");
                String name = (String) nodeInfo.get("name");
                String type = (String) nodeInfo.get("type");
                
                sb.append(indent).append("╔═══════════════════════════════════════════════════════════════════╗\n");
                if ("attacker".equals(type)) {
                    sb.append(indent).append("║                    【网侧】攻击者");
                    if (name != null) {
                        sb.append(" (").append(name).append(")");
                    }
                    sb.append("                                 ║\n");
                } else if ("victim".equals(type)) {
                    sb.append(indent).append("║                    【网侧】受害者 (桥接点)                        ║\n");
                } else if ("server".equals(type)) {
                    sb.append(indent).append("║                    【网侧】服务器节点");
                    if (name != null) {
                        sb.append(" (").append(name).append(")");
                    }
                    sb.append("                             ║\n");
                } else {
                    sb.append(indent).append("║                    【网侧】网络节点                                    ║\n");
                }
                sb.append(indent).append("╠═══════════════════════════════════════════════════════════════════╣\n");
                if (ip != null) {
                    sb.append(indent).append("║ 🌐 IP地址: ").append(ip).append("\n");
                }
                if (name != null) {
                    sb.append(indent).append("║ 📍 名称: ").append(name).append("\n");
                }
                if (type != null) {
                    sb.append(indent).append("║    类型: ").append("attacker".equals(type) ? "攻击者" : 
                             "victim".equals(type) ? "受害者" : 
                             "server".equals(type) ? "服务器" : type).append("\n");
                }
                sb.append(indent).append("╚═══════════════════════════════════════════════════════════════════╝\n");
            }
        } else if (isNetworkEventNode && node.getStoryNode() != null && node.getStoryNode().getOther() != null) {
            // 显示网络事件节点（如webshell上传）
            Map<String, Object> other = node.getStoryNode().getOther();
            
            sb.append(indent).append("╔═══════════════════════════════════════════════════════════════════╗\n");
            sb.append(indent).append("║                    【网侧】网络攻击事件                             ║\n");
            sb.append(indent).append("╠═══════════════════════════════════════════════════════════════════╣\n");
            sb.append(indent).append("║ 🌐 攻击者: ").append(other.get("srcAddress")).append(":").append(other.get("srcPort")).append("\n");
            sb.append(indent).append("║    协议: ").append(other.get("protocol")).append(" ").append(other.get("method")).append("\n");
            sb.append(indent).append("║    目标: ").append(other.get("destAddress")).append(":").append(other.get("destPort")).append("\n");
            if (other.get("url") != null) {
                sb.append(indent).append("║    URL: ").append(other.get("url")).append("\n");
            }
            if (other.get("ruleName") != null) {
                sb.append(indent).append("║    检测: ").append(other.get("ruleName")).append("\n");
            }
            if (other.get("attackTime") != null) {
                sb.append(indent).append("║    时间: ").append(other.get("attackTime")).append("\n");
            }
            String threat = node.getNodeThreatSeverity() != null ? node.getNodeThreatSeverity() : "UNKNOWN";
            String threatIcon = getThreatIcon(threat);
            sb.append(indent).append("║    ").append(threatIcon).append(" 威胁: ").append(threat).append("\n");
            sb.append(indent).append("╚═══════════════════════════════════════════════════════════════════╝\n");
        } else if (isProcessNode && node.getChainNode() != null && node.getChainNode().getProcessEntity() != null) {
            // 显示进程节点
            ProcessEntity entity = node.getChainNode().getProcessEntity();
            boolean isAlarm = node.getChainNode().getIsAlarm() != null && node.getChainNode().getIsAlarm();
            boolean isRoot = node.getChainNode().getIsRoot() != null && node.getChainNode().getIsRoot();
            boolean isExtend = node.getChainNode().getIsExtensionNode() != null && node.getChainNode().getIsExtensionNode();
            boolean isBroken = node.getChainNode().getIsBroken() != null && node.getChainNode().getIsBroken();
            
            String icon = isAlarm ? "🚨" : isRoot ? "⚡" : isExtend ? "🔗" : "💻";
            String boxStyle = isAlarm ? "━" : "─";
            
            sb.append(indent).append("┏").append(boxStyle.repeat(68)).append("┓\n");
            
            // 标题行 - 添加 processGuid
            String title = icon + " " + entity.getProcessName() + " (PID:" + entity.getProcessId() + ")";
            if (entity.getProcessGuid() != null && !entity.getProcessGuid().isEmpty()) {
                title += " [" + entity.getProcessGuid() + "]";
            }
            if (isAlarm) title += " ⚠️ 告警";
            if (isRoot) title += " 🎯 根";
            if (isExtend) title += " (扩展)";
            if (isBroken) title += " ⛓️ 断链";
            // 处理超长标题
            if (title.length() > 66) {
                sb.append(indent).append("┃ ").append(title.substring(0, 63)).append("... ┃\n");
            } else {
                sb.append(indent).append("┃ ").append(String.format("%-66s", title)).append(" ┃\n");
            }
            
            // 分隔线
            sb.append(indent).append("┃").append("─".repeat(68)).append("┃\n");
            
            // 用户信息
            String user = entity.getProcessUserName() != null ? entity.getProcessUserName() : "N/A";
            sb.append(indent).append("┃  👤 用户: ").append(String.format("%-55s", user)).append(" ┃\n");
            
            // 命令行
            String cmd = entity.getCommandLine() != null ? entity.getCommandLine() : "";
            if (cmd.length() > 55) {
                sb.append(indent).append("┃  📝 命令: ").append(cmd.substring(0, 52)).append("... ┃\n");
            } else {
                sb.append(indent).append("┃  📝 命令: ").append(String.format("%-55s", cmd)).append(" ┃\n");
            }
            
            // 启动时间
            String startTime = entity.getProcessStartTime() != null ? entity.getProcessStartTime() : "N/A";
            sb.append(indent).append("┃  🕐 时间: ").append(String.format("%-55s", startTime)).append(" ┃\n");
            
            // 威胁等级
            String threat = node.getNodeThreatSeverity() != null ? node.getNodeThreatSeverity() : "UNKNOWN";
            String threatIcon = getThreatIcon(threat);
            sb.append(indent).append("┃  ").append(threatIcon).append(" 威胁: ").append(String.format("%-55s", threat)).append(" ┃\n");
            
            // 告警详情
            if (isAlarm && node.getChainNode().getAlarmNodeInfo() != null) {
                AlarmNodeInfo alarm = node.getChainNode().getAlarmNodeInfo();
                sb.append(indent).append("┃").append("═".repeat(68)).append("┃\n");
                sb.append(indent).append("┃  🚨 告警: ").append(String.format("%-55s", alarm.getName())).append(" ┃\n");
                if (alarm.getRuleType() != null) {
                    sb.append(indent).append("┃     类型: ").append(String.format("%-55s", alarm.getRuleType())).append(" ┃\n");
                }
            }
            
            sb.append(indent).append("┗").append(boxStyle.repeat(68)).append("┛\n");
        } else if (isFileNode && node.getStoryNode() != null && node.getStoryNode().getOther() != null) {
            // 显示文件节点
            Map<String, Object> other = node.getStoryNode().getOther();
            
            sb.append(indent).append("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n");
            sb.append(indent).append("┃ 📄 恶意文件                                                        ┃\n");
            sb.append(indent).append("┃━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┃\n");
            sb.append(indent).append("┃    文件名: ").append(other.get("fileName")).append("\n");
            if (other.get("filePath") != null) {
                String path = other.get("filePath").toString();
                if (path.length() > 60) {
                    sb.append(indent).append("┃    路径: ").append(path.substring(0, 57)).append("...\n");
                } else {
                    sb.append(indent).append("┃    路径: ").append(path).append("\n");
                }
            }
            if (other.get("virusName") != null) {
                sb.append(indent).append("┃    病毒: ").append(other.get("virusName")).append("\n");
            }
            if (other.get("fileMd5") != null) {
                sb.append(indent).append("┃    MD5: ").append(other.get("fileMd5")).append("\n");
            }
            String threat = node.getNodeThreatSeverity() != null ? node.getNodeThreatSeverity() : "HIGH";
            String threatIcon = getThreatIcon(threat);
            sb.append(indent).append("┃    ").append(threatIcon).append(" 威胁: ").append(threat).append("\n");
            sb.append(indent).append("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n");
        } else {
            // 其他类型节点
            sb.append(indent).append("┏────────────────────────────────────────────────────────────────────┓\n");
            sb.append(indent).append("┃ 🔹 ").append(node.getNodeId());
            if (node.getStoryNode() != null && node.getStoryNode().getType() != null) {
                sb.append(" (").append(node.getStoryNode().getType()).append(")");
            }
            sb.append("\n");
            sb.append(indent).append("┗────────────────────────────────────────────────────────────────────┛\n");
        }
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
     * 构建完整的攻击链路径（完全基于边关系）
     * 策略：找到起点节点（没有入边的节点），然后按照边关系顺序遍历
     */
    private static List<ChainStep> buildFullChainPath(String startNodeId, Map<String, ProcessNode> nodeMap, 
                                                       List<ProcessEdge> edges) {
        List<ChainStep> result = new ArrayList<>();
        
        // 构建类型标识符到节点ID的映射（用于处理 server/victim/attacker 等标识符）
        Map<String, String> typeToNodeId = new HashMap<>();
        for (Map.Entry<String, ProcessNode> entry : nodeMap.entrySet()) {
            ProcessNode node = entry.getValue();
            if (node.getStoryNode() != null && node.getStoryNode().getNode() != null) {
                Map<String, Object> nodeInfo = node.getStoryNode().getNode();
                String type = (String) nodeInfo.get("type");
                if (type != null) {
                    typeToNodeId.put(type, entry.getKey());
                }
            }
        }
        
        // 转换边关系中的类型标识符为实际的nodeId，并构建完整的边映射
        Map<String, String> childToParent = new HashMap<>();  // child -> parent
        Map<String, List<String>> parentToChildren = new HashMap<>();  // parent -> list of children
        Map<String, String> edgeDescriptions = new HashMap<>();  // child -> edge description
        
        if (edges != null) {
            for (ProcessEdge edge : edges) {
                String sourceId = edge.getSource();
                String targetId = edge.getTarget();
                
                // 如果source/target是类型标识符（如"server", "victim"），转换为实际的nodeId
                if (!nodeMap.containsKey(sourceId) && typeToNodeId.containsKey(sourceId)) {
                    sourceId = typeToNodeId.get(sourceId);
                    System.out.println("DEBUG: 转换 source " + edge.getSource() + " -> " + sourceId);
                }
                if (!nodeMap.containsKey(targetId) && typeToNodeId.containsKey(targetId)) {
                    targetId = typeToNodeId.get(targetId);
                    System.out.println("DEBUG: 转换 target " + edge.getTarget() + " -> " + targetId);
                }
                
                // 只有转换后的ID在nodeMap中存在，才添加边关系
                if (nodeMap.containsKey(sourceId) && nodeMap.containsKey(targetId)) {
                    childToParent.put(targetId, sourceId);
                    parentToChildren.computeIfAbsent(sourceId, k -> new ArrayList<>()).add(targetId);
                    edgeDescriptions.put(targetId, edge.getVal() != null ? edge.getVal() : "");
                    System.out.println("DEBUG: 添加边 " + sourceId + " -> " + targetId + " (描述: " + edge.getVal() + ")");
                } else {
                    System.out.println("DEBUG: 跳过边 " + sourceId + " -> " + targetId + " (节点不存在)");
                }
            }
        }
        
        // 找到所有起点节点（没有入边的节点）
        // 起点节点：不在childToParent的key中（即没有其他节点指向它）
        Set<String> startNodes = new HashSet<>();
        for (String nodeId : nodeMap.keySet()) {
            if (!childToParent.containsKey(nodeId)) {
                // 如果这个节点有出边（是某个链路的起点），才认为是起点节点
                if (parentToChildren.containsKey(nodeId) && !parentToChildren.get(nodeId).isEmpty()) {
                    startNodes.add(nodeId);
                }
            }
        }
        
        // 如果没有找到起点节点，使用startNodeId（从根节点开始）
        if (startNodes.isEmpty()) {
            startNodes.add(startNodeId);
            System.out.println("DEBUG: 未找到起点节点，使用startNodeId: " + startNodeId);
        }
        
        System.out.println("DEBUG: 起点节点: " + startNodes);
        
        // 从每个起点节点开始，按照边关系深度优先遍历
        Set<String> visited = new HashSet<>();
        for (String startNode : startNodes) {
            buildPathFromEdges(startNode, nodeMap, parentToChildren, edgeDescriptions, result, visited);
        }
        
        return result;
    }
    
    /**
     * 根据边关系递归构建路径
     */
    private static void buildPathFromEdges(String nodeId, Map<String, ProcessNode> nodeMap,
                                           Map<String, List<String>> parentToChildren,
                                           Map<String, String> edgeDescriptions,
                                           List<ChainStep> result,
                                           Set<String> visited) {
        if (nodeId == null || visited.contains(nodeId)) {
            return;
        }
        
        ProcessNode node = nodeMap.get(nodeId);
        if (node == null) {
            System.out.println("DEBUG: 节点不存在: " + nodeId);
            return;
        }
        
        visited.add(nodeId);
        
        // 获取指向当前节点的边描述
        // edgeDescriptions存储的是 child -> description，所以直接获取即可
        String edgeDesc = edgeDescriptions.get(nodeId);
        
        result.add(new ChainStep(node, edgeDesc));
        System.out.println("DEBUG: 添加节点到链路: " + nodeId + " (边描述: " + edgeDesc + ")");
        
        // 获取当前节点的所有子节点（通过边关系）
        List<String> children = parentToChildren.get(nodeId);
        if (children != null && !children.isEmpty()) {
            System.out.println("DEBUG: 节点 " + nodeId + " 有 " + children.size() + " 个子节点: " + children);
            
            // 如果有多个子节点，优先遍历桥接到端侧的边（边描述为"桥接"的）
            // 其次遍历其他边，保持边关系的逻辑顺序
            List<String> sortedChildren = new ArrayList<>(children);
            sortedChildren.sort((a, b) -> {
                String descA = edgeDescriptions.get(a);
                String descB = edgeDescriptions.get(b);
                
                // 优先显示"桥接"边
                boolean isBridgeA = "桥接".equals(descA);
                boolean isBridgeB = "桥接".equals(descB);
                
                if (isBridgeA && !isBridgeB) return -1;
                if (!isBridgeA && isBridgeB) return 1;
                
                // 其次优先显示"段链"边
                boolean isSegmentA = "段链".equals(descA);
                boolean isSegmentB = "段链".equals(descB);
                
                if (isSegmentA && !isSegmentB) return -1;
                if (!isSegmentA && isSegmentB) return 1;
                
                // 其他情况保持原顺序
                return 0;
            });
            
            for (String childId : sortedChildren) {
                buildPathFromEdges(childId, nodeMap, parentToChildren, edgeDescriptions, result, visited);
            }
        } else {
            System.out.println("DEBUG: 节点 " + nodeId + " 没有子节点");
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
            
            // 进程信息 - 添加 processGuid
            if (chainNode.getProcessEntity() != null) {
                ProcessEntity entity = chainNode.getProcessEntity();
                sb.append(entity.getProcessName());
                if (entity.getProcessId() != null) {
                    sb.append(" (PID:").append(entity.getProcessId()).append(")");
                }
                if (entity.getProcessGuid() != null && !entity.getProcessGuid().isEmpty()) {
                    sb.append(" [").append(entity.getProcessGuid()).append("]");
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
            // 故事线节点（网络、文件、IP等）
            StoryNode storyNode = node.getStoryNode();
            
            if ("srcNode".equals(storyNode.getType())) {
                // IP节点 - 显示IP和类型
                Map<String, Object> nodeInfo = storyNode.getNode();
                if (nodeInfo != null) {
                    String ip = (String) nodeInfo.get("ip");
                    String type = (String) nodeInfo.get("type");
                    sb.append("🌐 [IP节点] ").append(ip);
                    if ("attacker".equals(type)) {
                        sb.append(" (攻击者)");
                    } else if ("victim".equals(type)) {
                        sb.append(" (受害者)");
                    }
                } else {
                    sb.append("[").append(storyNode.getType()).append("] IP节点");
                }
            } else if ("NETWORK".equalsIgnoreCase(node.getLogType())) {
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
     * 链路步骤，用于表示完整攻击链中的一个节点及其与下一个节点的关系
     */
    static class ChainStep {
        ProcessNode node;
        String edgeDescription;  // 连接到下一个节点的边描述
        
        ChainStep(ProcessNode node, String edgeDescription) {
            this.node = node;
            this.edgeDescription = edgeDescription;
        }
    }
    
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
        private Map<String, Object> node;  // 用于IP节点等
        
        // Getters and Setters
        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        
        public Map<String, Object> getOther() { return other; }
        public void setOther(Map<String, Object> other) { this.other = other; }
        
        public Map<String, Object> getNode() { return node; }
        public void setNode(Map<String, Object> node) { this.node = node; }
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

