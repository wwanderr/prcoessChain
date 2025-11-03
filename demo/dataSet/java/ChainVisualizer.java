import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * 直接从test_data.txt生成链关系图
 */
public class ChainVisualizer {
    private static final ObjectMapper mapper = new ObjectMapper();
    
    static class ProcessNode {
        String processGuid;
        String parentProcessGuid;
        String processName;
        int processId;
        String processUserName;
        String traceId;
        String logType;
        String threatLevel = "LOW";
        List<ProcessNode> children = new ArrayList<>();
        boolean isRoot = false;
        boolean isAlarm = false;
        
        String getSimpleUserName() {
            if (processUserName == null) return "SYSTEM";
            int idx = processUserName.lastIndexOf('\\');
            return idx >= 0 ? processUserName.substring(idx + 1) : processUserName;
        }
    }
    
    static class NetworkNode {
        String srcAddress;
        String destAddress;
        int srcPort;
        int destPort;
        String protocol = "TCP";
        String attackType = "webshell_upload";
    }
    
    static class FileNode {
        String fileName;
        String virusName;
        String filePath;
    }
    
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("用法: java ChainVisualizer <test_data.txt路径>");
            return;
        }
        
        String inputFile = args[0];
        String outputFile = inputFile.replace("test_data.txt", "链关系图.md");
        
        try {
            generateChainDiagram(inputFile, outputFile);
            System.out.println("✓ 链关系图已生成: " + outputFile);
        } catch (Exception e) {
            System.err.println("× 生成失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void generateChainDiagram(String inputFile, String outputFile) throws IOException {
        // 读取并解析所有日志
        List<ProcessNode> processes = new ArrayList<>();
        Map<String, ProcessNode> processMap = new HashMap<>();
        NetworkNode network = null;
        FileNode file = null;
        String rootTraceId = null;
        
        List<String> lines = Files.readAllLines(Paths.get(inputFile), StandardCharsets.UTF_8);
        
        for (String line : lines) {
            if (line.trim().isEmpty()) continue;
            
            JsonNode json = mapper.readTree(line);
            String logType = json.has("logType") ? json.get("logType").asText() : "";
            
            if ("network".equals(logType) || "alert".equals(logType)) {
                network = new NetworkNode();
                network.srcAddress = json.has("srcAddress") ? json.get("srcAddress").asText() : "";
                network.destAddress = json.has("destAddress") ? json.get("destAddress").asText() : "";
                if (json.has("srcPort")) {
                    String srcPortStr = json.get("srcPort").asText();
                    try { network.srcPort = Integer.parseInt(srcPortStr); } catch (Exception e) { }
                }
                if (json.has("destPort")) {
                    String destPortStr = json.get("destPort").asText();
                    try { network.destPort = Integer.parseInt(destPortStr); } catch (Exception e) { }
                }
                if (json.has("name")) {
                    String name = json.get("name").asText();
                    if (name.contains("命令执行")) network.attackType = "command_execution";
                    else if (name.contains("矿池")) network.attackType = "mining_pool";
                }
                if (json.has("appProtocol")) {
                    network.protocol = json.get("appProtocol").asText().toUpperCase();
                }
            } else if ("file".equals(logType)) {
                file = new FileNode();
                file.fileName = json.has("fileName") ? json.get("fileName").asText() : "";
                file.virusName = json.has("virusName") ? json.get("virusName").asText() : "";
                file.filePath = json.has("filePath") ? json.get("filePath").asText() : "";
            } else if ("process".equals(logType)) {
                ProcessNode node = new ProcessNode();
                node.processGuid = json.has("processGuid") ? json.get("processGuid").asText() : "";
                node.parentProcessGuid = json.has("parentProcessGuid") ? json.get("parentProcessGuid").asText() : "";
                node.processName = json.has("processName") ? json.get("processName").asText() : "";
                node.processId = json.has("processId") ? json.get("processId").asInt() : 0;
                node.processUserName = json.has("processUserName") ? json.get("processUserName").asText() : "SYSTEM";
                node.traceId = json.has("traceId") ? json.get("traceId").asText() : "";
                node.logType = logType;
                
                // 检测根节点：processGuid == traceId
                if (node.processGuid.equals(node.traceId)) {
                    node.isRoot = true;
                    node.isAlarm = true;
                    node.threatLevel = "HIGH";
                    rootTraceId = node.traceId;
                }
                
                processes.add(node);
                processMap.put(node.processGuid, node);
            }
        }
        
        // 构建进程树
        ProcessNode rootNode = null;
        for (ProcessNode node : processes) {
            if (node.isRoot) {
                rootNode = node;
            }
            if (node.parentProcessGuid != null && !node.parentProcessGuid.isEmpty()) {
                ProcessNode parent = processMap.get(node.parentProcessGuid);
                if (parent != null) {
                    parent.children.add(node);
                }
            }
        }
        
        // 如果没找到根节点，尝试找告警节点
        if (rootNode == null) {
            for (ProcessNode node : processes) {
                if (node.threatLevel.equals("HIGH")) {
                    rootNode = node;
                    break;
                }
            }
        }
        
        // 生成Markdown
        StringBuilder sb = new StringBuilder();
        sb.append("# 进程链关系图\n\n");
        sb.append("**图例说明**:\n");
        sb.append("- 🌐 网络攻击源\n");
        sb.append("- 💻 进程节点\n");
        sb.append("- 📄 文件节点\n");
        sb.append("- [ROOT] 根节点（告警进程）\n");
        sb.append("- [ALARM] 告警节点\n");
        sb.append("- [EXTEND] 扩展节点（有子进程的节点）\n");
        sb.append("- 威胁等级: HIGH (高) | MEDIUM (中) | LOW (低)\n\n");
        sb.append("---\n\n");
        sb.append("## 完整进程树视图\n\n");
        sb.append("```\n");
        
        // 从网络节点开始绘制
        if (network != null) {
            sb.append(String.format("└── 🌐 [%s] %s:%d → %s:%d (%s) [HIGH]\n",
                    network.attackType,
                    network.srcAddress, network.srcPort,
                    network.destAddress, network.destPort,
                    network.protocol));
        }
        
        // 找到最顶层的父进程（没有父进程或父进程不存在的）
        List<ProcessNode> topNodes = new ArrayList<>();
        for (ProcessNode node : processes) {
            if (node.parentProcessGuid == null || node.parentProcessGuid.isEmpty() 
                    || !processMap.containsKey(node.parentProcessGuid)) {
                topNodes.add(node);
            }
        }
        
        // 按照traceId排序，根节点的traceId优先
        final String finalRootTraceId = rootTraceId;
        topNodes.sort((a, b) -> {
            if (a.traceId.equals(finalRootTraceId)) return -1;
            if (b.traceId.equals(finalRootTraceId)) return 1;
            return a.traceId.compareTo(b.traceId);
        });
        
        // 绘制进程树
        for (int i = 0; i < topNodes.size(); i++) {
            ProcessNode topNode = topNodes.get(i);
            boolean isLast = (i == topNodes.size() - 1);
            drawProcessTree(sb, topNode, "    ", isLast, rootTraceId);
        }
        
        // 添加文件节点 (简化版，不计算深度，避免StackOverflow)
        if (file != null) {
            sb.append(String.format("    └── 📄 [file] %s (%s) [HIGH]\n",
                    file.fileName, file.virusName));
        }
        
        sb.append("```\n\n");
        
        // 统计信息
        sb.append("### 统计信息\n\n");
        sb.append(String.format("- **进程节点数**: %d\n", processes.size()));
        sb.append(String.format("- **文件节点数**: %d\n", file != null ? 1 : 0));
        sb.append(String.format("- **网络节点数**: %d\n", network != null ? 1 : 0));
        sb.append(String.format("- **总节点数**: %d\n", 
                processes.size() + (file != null ? 1 : 0) + (network != null ? 1 : 0)));
        sb.append(String.format("- **根进程数**: 1\n"));
        if (rootNode != null) {
            sb.append(String.format("- **告警进程**: %s (PID:%d)\n", 
                    rootNode.processName, rootNode.processId));
        }
        if (file != null) {
            sb.append(String.format("- **恶意文件**: %s (%s)\n", file.fileName, file.virusName));
        }
        sb.append("\n---\n\n");
        
        // 写入文件
        Files.write(Paths.get(outputFile), sb.toString().getBytes(StandardCharsets.UTF_8));
    }
    
    private static void drawProcessTree(StringBuilder sb, ProcessNode node, String prefix,
                                       boolean isLast, String rootTraceId) {
        drawProcessTree(sb, node, prefix, isLast, rootTraceId, new HashSet<>(), 0);
    }
    
    private static void drawProcessTree(StringBuilder sb, ProcessNode node, String prefix,
                                       boolean isLast, String rootTraceId, Set<String> visited, int depth) {
        // 防止递归过深
        if (depth > 100) {
            sb.append(prefix);
            sb.append(isLast ? "└── " : "├── ");
            sb.append(String.format("💻 [TOO_DEEP] %s (PID:%d) - depth limit reached\n",
                    node.processName, node.processId));
            return;
        }
        
        // 防止循环引用
        if (visited.contains(node.processGuid)) {
            sb.append(prefix);
            sb.append(isLast ? "└── " : "├── ");
            sb.append(String.format("💻 [CIRCULAR] %s (PID:%d) - already visited\n",
                    node.processName, node.processId));
            return;
        }
        visited.add(node.processGuid);
        
        // 构建节点标签
        List<String> labels = new ArrayList<>();
        if (!node.children.isEmpty()) labels.add("EXTEND");
        if (node.isRoot) labels.add("ROOT");
        if (node.isAlarm) labels.add("ALARM");
        
        String labelStr = labels.isEmpty() ? "" : "[" + String.join(",", labels) + "] ";
        
        // 获取威胁等级
        String threat = node.threatLevel;
        if (node.isAlarm) threat = "HIGH";
        else if (node.processName.contains("cgi") || node.processName.contains("php")) threat = "MEDIUM";
        
        // 绘制当前节点
        sb.append(prefix);
        sb.append(isLast ? "└── " : "├── ");
        sb.append(String.format("💻 %s%s (PID:%d) - %s [%s]\n",
                labelStr, node.processName, node.processId, 
                node.getSimpleUserName(), threat));
        
        // 绘制子进程
        if (!node.children.isEmpty()) {
            // 按processId排序
            node.children.sort(Comparator.comparingInt(n -> n.processId));
            
            String childPrefix = prefix + (isLast ? "    " : "│   ");
            for (int i = 0; i < node.children.size(); i++) {
                ProcessNode child = node.children.get(i);
                boolean isLastChild = (i == node.children.size() - 1);
                drawProcessTree(sb, child, childPrefix, isLastChild, rootTraceId, visited, depth + 1);
            }
        }
    }
    
    private static int getDepth(ProcessNode node, List<ProcessNode> allNodes) {
        int depth = 0;
        ProcessNode current = node;
        Map<String, ProcessNode> map = new HashMap<>();
        for (ProcessNode n : allNodes) {
            map.put(n.processGuid, n);
        }
        
        while (current.parentProcessGuid != null && map.containsKey(current.parentProcessGuid)) {
            current = map.get(current.parentProcessGuid);
            depth++;
            if (depth > 20) break; // 防止循环
        }
        return depth;
    }
    
    // 检查node是否是ancestor的后代
    private static boolean isDescendantOf(ProcessNode node, ProcessNode ancestor, Map<String, ProcessNode> processMap) {
        ProcessNode current = node;
        int maxDepth = 50;
        while (current != null && maxDepth-- > 0) {
            if (current == ancestor) {
                return true;
            }
            if (current.parentProcessGuid != null && processMap.containsKey(current.parentProcessGuid)) {
                current = processMap.get(current.parentProcessGuid);
            } else {
                break;
            }
        }
        return false;
    }
}

