import java.io.*;
import java.util.*;
import java.util.regex.*;

public class SimpleVisualizer {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("用法: java SimpleVisualizer <test_data.txt路径>");
            return;
        }
        
        String inputFile = args[0];
        String outputFile = inputFile.replace("test_data.txt", "链关系图.md");
        
        try {
            generateChainDiagram(inputFile, outputFile);
            System.out.println("链关系图已生成: " + outputFile);
        } catch (Exception e) {
            System.err.println("生成失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void generateChainDiagram(String inputFile, String outputFile) throws IOException {
        List<ProcessInfo> processes = new ArrayList<>();
        Map<String, ProcessInfo> processMap = new HashMap<>();
        
        // 读取并解析进程数据
        try (BufferedReader reader = new BufferedReader(new FileReader(inputFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || !line.startsWith("{")) continue;
                
                ProcessInfo process = parseProcess(line);
                if (process != null && "process".equals(process.logType)) {
                    processes.add(process);
                    processMap.put(process.processGuid, process);
                }
            }
        }
        
        // 生成链关系图
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile, false))) {
            writer.println("# 进程链关系图");
            writer.println();
            
            // 按traceId分组
            Map<String, List<ProcessInfo>> traceGroups = new HashMap<>();
            for (ProcessInfo p : processes) {
                traceGroups.computeIfAbsent(p.traceId, k -> new ArrayList<>()).add(p);
            }
            
            for (Map.Entry<String, List<ProcessInfo>> entry : traceGroups.entrySet()) {
                String traceId = entry.getKey();
                List<ProcessInfo> traceProcesses = entry.getValue();
                
                writer.println("## TraceID: " + traceId);
                writer.println();
                
                // 找根节点 (processGuid == traceId 的节点)
                ProcessInfo root = null;
                for (ProcessInfo p : traceProcesses) {
                    if (p.processGuid.equals(traceId)) {
                        root = p;
                        break;
                    }
                }
                
                if (root != null) {
                    writer.println("**根节点**: " + root.processName + " (PID:" + root.processId + ")");
                    writer.println();
                    
                    // 构建树结构
                    buildTree(writer, root, processMap, "", new HashSet<>());
                } else {
                    writer.println("**进程列表**:");
                    for (ProcessInfo p : traceProcesses) {
                        writer.println("- " + p.processName + " (PID:" + p.processId + ", GUID:" + p.processGuid + ")");
                    }
                }
                writer.println();
            }
            
            // 添加完整进程列表
            writer.println("## 完整进程列表");
            writer.println();
            writer.println("| 进程名 | PID | GUID | 父GUID | TraceID |");
            writer.println("|--------|-----|------|--------|---------|");
            
            for (ProcessInfo p : processes) {
                writer.printf("| %s | %d | %s | %s | %s |%n",
                    p.processName, p.processId, p.processGuid, 
                    p.parentProcessGuid != null ? p.parentProcessGuid : "N/A", p.traceId);
            }
        }
    }
    
    private static void buildTree(PrintWriter writer, ProcessInfo current, Map<String, ProcessInfo> processMap, 
                                 String indent, Set<String> visited) {
        if (visited.contains(current.processGuid)) {
            return; // 防止循环
        }
        visited.add(current.processGuid);
        
        writer.println(indent + "├─ " + current.processName + " (PID:" + current.processId + ")");
        
        // 查找子进程
        List<ProcessInfo> children = new ArrayList<>();
        for (ProcessInfo p : processMap.values()) {
            if (current.processGuid.equals(p.parentProcessGuid) && !visited.contains(p.processGuid)) {
                children.add(p);
            }
        }
        
        // 递归处理子进程
        for (int i = 0; i < children.size(); i++) {
            ProcessInfo child = children.get(i);
            String newIndent = indent + (i == children.size() - 1 ? "   " : "│  ");
            buildTree(writer, child, processMap, newIndent, new HashSet<>(visited));
        }
    }
    
    private static ProcessInfo parseProcess(String jsonLine) {
        try {
            ProcessInfo info = new ProcessInfo();
            
            // 简单的JSON解析
            info.processGuid = extractJsonValue(jsonLine, "processGuid");
            info.parentProcessGuid = extractJsonValue(jsonLine, "parentProcessGuid");
            info.processName = extractJsonValue(jsonLine, "processName");
            info.logType = extractJsonValue(jsonLine, "logType");
            info.traceId = extractJsonValue(jsonLine, "traceId");
            
            String pidStr = extractJsonValue(jsonLine, "processId");
            if (pidStr != null && !pidStr.isEmpty()) {
                info.processId = Integer.parseInt(pidStr);
            }
            
            return info;
        } catch (Exception e) {
            return null;
        }
    }
    
    private static String extractJsonValue(String json, String key) {
        Pattern pattern = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        
        // 尝试数字值
        Pattern numPattern = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)");
        Matcher numMatcher = numPattern.matcher(json);
        if (numMatcher.find()) {
            return numMatcher.group(1);
        }
        
        return null;
    }
    
    static class ProcessInfo {
        String processGuid;
        String parentProcessGuid;
        String processName;
        String logType;
        String traceId;
        int processId;
    }
}

