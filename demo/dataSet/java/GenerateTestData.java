import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * 测试数据生成器
 * 用于生成webshell文件上传、命令执行、矿池等场景的测试数据
 * 
 * 使用方法:
 * javac -cp .:jackson-databind-2.13.0.jar:jackson-core-2.13.0.jar:jackson-annotations-2.13.0.jar GenerateTestData.java
 * java -cp .:jackson-databind-2.13.0.jar:jackson-core-2.13.0.jar:jackson-annotations-2.13.0.jar GenerateTestData
 */
public class GenerateTestData {
    
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final Random random = new Random();
    
    // 场景配置
    static class ScenarioConfig {
        String scenarioName;      // 场景名称：webshell文件上传、命令执行、矿池
        int caseNumber;           // 案例编号
        int layers;               // 层数
        int totalNodes;           // 总节点数
        boolean hasBranches;      // 是否有分支
        int branchCount;          // 分支数量
        String baseIP;            // 基础IP
        String traceId;           // traceId
        String productVendor;     // 产品厂商
        
        ScenarioConfig(String scenarioName, int caseNumber, int layers, int totalNodes, 
                      boolean hasBranches, int branchCount, String baseIP, String traceId, String productVendor) {
            this.scenarioName = scenarioName;
            this.caseNumber = caseNumber;
            this.layers = layers;
            this.totalNodes = totalNodes;
            this.hasBranches = hasBranches;
            this.branchCount = branchCount;
            this.baseIP = baseIP;
            this.traceId = traceId;
            this.productVendor = productVendor;
        }
    }
    
    public static void main(String[] args) throws IOException {
        System.out.println("=== 开始生成测试数据 ===\n");
        
        // WebShell文件上传场景
        generateWebShellScenarios();
        
        // 命令执行场景
        generateCommandExecScenarios();
        
        // 矿池场景
        generateMinerScenarios();
        
        System.out.println("\n=== 所有测试数据生成完成 ===");
    }
    
    /**
     * 生成WebShell文件上传场景
     */
    private static void generateWebShellScenarios() throws IOException {
        System.out.println("【WebShell文件上传】场景生成中...");
        
        List<ScenarioConfig> configs = Arrays.asList(
            new ScenarioConfig("webshell文件上传", 2, 5, 15, false, 0, "10.50.110.193", "traceId-986", "Qihoo360"),
            new ScenarioConfig("webshell文件上传", 3, 6, 25, true, 2, "10.50.111.194", "traceId-987", "Kaspersky"),
            new ScenarioConfig("webshell文件上传", 4, 8, 40, false, 0, "10.50.112.195", "traceId-988", "Symantec"),
            new ScenarioConfig("webshell文件上传", 5, 8, 120, true, 3, "10.50.113.196", "traceId-989", "TrendMicro")
        );
        
        for (ScenarioConfig config : configs) {
            generateScenarioData(config);
        }
    }
    
    /**
     * 生成命令执行场景
     */
    private static void generateCommandExecScenarios() throws IOException {
        System.out.println("\n【命令执行】场景生成中...");
        
        List<ScenarioConfig> configs = Arrays.asList(
            new ScenarioConfig("命令执行", 2, 5, 12, false, 0, "10.50.114.197", "traceId-211", "McAfee"),
            new ScenarioConfig("命令执行", 3, 6, 22, true, 2, "10.50.115.198", "traceId-212", "Sophos"),
            new ScenarioConfig("命令执行", 4, 7, 35, false, 0, "10.50.116.199", "traceId-213", "ESET"),
            new ScenarioConfig("命令执行", 5, 8, 110, true, 3, "10.50.117.200", "traceId-214", "Bitdefender")
        );
        
        for (ScenarioConfig config : configs) {
            generateScenarioData(config);
        }
    }
    
    /**
     * 生成矿池场景
     */
    private static void generateMinerScenarios() throws IOException {
        System.out.println("\n【矿池】场景生成中...");
        
        List<ScenarioConfig> configs = Arrays.asList(
            new ScenarioConfig("矿池", 2, 5, 10, false, 0, "10.50.118.201", "traceId-205", "Avast"),
            new ScenarioConfig("矿池", 3, 6, 20, true, 2, "10.50.119.202", "traceId-206", "AVG"),
            new ScenarioConfig("矿池", 4, 7, 38, false, 0, "10.50.120.203", "traceId-207", "Panda"),
            new ScenarioConfig("矿池", 5, 8, 115, true, 3, "10.50.121.204", "traceId-208", "Comodo")
        );
        
        for (ScenarioConfig config : configs) {
            generateScenarioData(config);
        }
    }
    
    /**
     * 生成单个场景的数据
     */
    private static void generateScenarioData(ScenarioConfig config) throws IOException {
        String dirPath = String.format("../%s/案例%d", config.scenarioName, config.caseNumber);
        File dir = new File(dirPath);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        
        String filePath = dirPath + "/test_data.txt";
        try (FileWriter writer = new FileWriter(filePath)) {
            // 第1行：网侧数据
            String networkData = generateNetworkData(config);
            writer.write(networkData + "\n");
            
            // 后续行：端侧数据（进程链）
            List<String> endpointDataList = generateEndpointData(config);
            for (String endpointData : endpointDataList) {
                writer.write(endpointData + "\n");
            }
        }
        
        System.out.println(String.format("  ✓ 案例%d: %d层, %d节点 -> %s", 
            config.caseNumber, config.layers, config.totalNodes, filePath));
    }
    
    /**
     * 生成网侧数据（告警）
     */
    private static String generateNetworkData(ScenarioConfig config) throws IOException {
        ObjectNode network = mapper.createObjectNode();
        
        // 基础信息
        network.put("sendHostAddress", "10.50.86.14");
        network.put("srcAddress", "10.50.86.15" + config.caseNumber);
        network.put("destAddress", config.baseIP);
        network.put("destPort", "80");
        network.put("logType", "alert");
        network.put("severity", "7");
        network.put("confidence", "High");
        
        // 根据场景类型设置不同的规则
        if (config.scenarioName.equals("webshell文件上传")) {
            network.put("ruleName", "检测到上传冰蝎webshell文件(PHP)");
            network.put("ruleType", "/WebAttack/WebshellUpload");
            network.put("incidentName", "Webshell后门访问事件");
        } else if (config.scenarioName.equals("命令执行")) {
            network.put("ruleName", "通用命令执行攻击");
            network.put("ruleType", "/WebAttack/CommandExec");
            network.put("incidentName", "命令执行攻击事件");
        } else if (config.scenarioName.equals("矿池")) {
            network.put("ruleName", "Symmi家族挖矿软件回连活动事件");
            network.put("ruleType", "/Malware/Miner");
            network.put("incidentName", "Symmi恶意家族活动事件");
        }
        
        // 时间戳
        network.put("startTime", "2025-05-23 15:31:06");
        network.put("@timestamp", "2025-05-23T07:31:06.000Z");
        
        // 其他必需字段
        network.put("direction", "00");
        network.put("netId", "7effcbb7-0c7a-4da9-bde1-32d06166acae");
        network.put("srcOrgId", "7effcbb7-0c7a-4da9-bde1-32d06166acae");
        network.put("destOrgId", "7effcbb7-0c7a-4da9-bde1-32d06166acae");
        
        return mapper.writeValueAsString(network);
    }
    
    /**
     * 生成端侧数据（进程链）
     */
    private static List<String> generateEndpointData(ScenarioConfig config) throws IOException {
        List<String> result = new ArrayList<>();
        List<ProcessNode> nodes = new ArrayList<>();
        
        // 计算每层的节点数
        int[] nodesPerLayer = calculateNodesPerLayer(config);
        
        // 生成进程链
        String currentGuid = config.traceId;
        String parentGuid = null;
        int nodeIndex = 0;
        
        for (int layer = 0; layer < config.layers; layer++) {
            int nodesInThisLayer = nodesPerLayer[layer];
            
            for (int i = 0; i < nodesInThisLayer; i++) {
                ProcessNode node = new ProcessNode();
                node.processGuid = (layer == 0 && i == 0) ? config.traceId : generateGuid();
                node.parentProcessGuid = parentGuid;
                node.processName = getProcessName(config.scenarioName, layer, i);
                node.processId = 1000 + nodeIndex;
                node.parentProcessId = (parentGuid != null) ? (1000 + nodeIndex - 1) : 0;
                node.layer = layer;
                node.hostAddress = config.baseIP;
                node.productVendorName = config.productVendorName;
                node.traceId = config.traceId;
                
                nodes.add(node);
                
                // 为下一层准备父节点
                if (i == 0) {
                    parentGuid = node.processGuid;
                }
                
                nodeIndex++;
            }
        }
        
        // 转换为JSON
        for (ProcessNode node : nodes) {
            result.add(nodeToJson(node));
        }
        
        return result;
    }
    
    /**
     * 计算每层的节点数
     */
    private static int[] calculateNodesPerLayer(ScenarioConfig config) {
        int[] result = new int[config.layers];
        
        if (!config.hasBranches) {
            // 线性链：平均分配
            int avgNodes = config.totalNodes / config.layers;
            int remainder = config.totalNodes % config.layers;
            
            for (int i = 0; i < config.layers; i++) {
                result[i] = avgNodes + (i < remainder ? 1 : 0);
            }
        } else {
            // 分支链：前几层少，后几层多
            result[0] = 1; // 根节点
            int remaining = config.totalNodes - 1;
            
            for (int i = 1; i < config.layers; i++) {
                if (i == config.layers - 1) {
                    result[i] = remaining;
                } else {
                    int nodes = Math.max(1, remaining / (config.layers - i) + random.nextInt(3));
                    result[i] = Math.min(nodes, remaining);
                    remaining -= result[i];
                }
            }
        }
        
        return result;
    }
    
    /**
     * 根据场景和层级获取进程名
     */
    private static String getProcessName(String scenario, int layer, int index) {
        if (scenario.equals("webshell文件上传")) {
            String[] names = {"php-cgi.exe", "xp.cn_cgi.exe", "phpstudy_pro.exe", "RuntimeBroker.exe", "svchost.exe", "services.exe", "wininit.exe", "System"};
            return names[Math.min(layer, names.length - 1)];
        } else if (scenario.equals("命令执行")) {
            String[] names = {"whoami.exe", "cmd.exe", "php-cgi.exe", "nginx.exe", "svchost.exe", "services.exe", "wininit.exe", "System"};
            return names[Math.min(layer, names.length - 1)];
        } else {
            String[] names = {"MsCpuCN64.exe", "powershell.exe", "cmd.exe", "explorer.exe", "svchost.exe", "services.exe", "wininit.exe", "System"};
            return names[Math.min(layer, names.length - 1)];
        }
    }
    
    /**
     * 生成GUID
     */
    private static String generateGuid() {
        return String.format("%016X", random.nextLong() & Long.MAX_VALUE);
    }
    
    /**
     * 将ProcessNode转换为JSON字符串
     */
    private static String nodeToJson(ProcessNode node) throws IOException {
        ObjectNode json = mapper.createObjectNode();
        
        json.put("processGuid", node.processGuid);
        if (node.parentProcessGuid != null) {
            json.put("parentProcessGuid", node.parentProcessGuid);
        }
        json.put("processName", node.processName);
        json.put("processId", node.processId);
        json.put("parentProcessId", node.parentProcessId);
        json.put("commandLine", node.processName);
        json.put("image", "C:\\\\Windows\\\\System32\\\\" + node.processName);
        json.put("processMd5", generateMd5());
        json.put("processUserName", "DESKTOP-M0S0L3H\\\\Administrator");
        json.put("processStartTime", "2025-05-21 09:" + (50 + node.layer) + ":00");
        json.put("logType", node.layer == 0 ? "file" : "process");
        json.put("opType", "create");
        json.put("hostAddress", node.hostAddress);
        json.put("hostName", "DESKTOP-M0S0L3H");
        json.put("srcAddress", node.hostAddress);
        json.put("destAddress", node.hostAddress);
        json.put("severity", node.layer == 0 ? 7 : 0);
        json.put("productVendorName", node.productVendorName);
        json.put("traceId", node.traceId);
        json.put("direction", "00");
        json.put("netId", "7effcbb7-0c7a-4da9-bde1-32d06166acae");
        json.put("srcOrgId", "7effcbb7-0c7a-4da9-bde1-32d06166acae");
        json.put("destOrgId", "7effcbb7-0c7a-4da9-bde1-32d06166acae");
        json.put("@timestamp", "2025-05-21T01:" + (50 + node.layer) + ":00.000Z");
        
        return mapper.writeValueAsString(json);
    }
    
    /**
     * 生成MD5
     */
    private static String generateMd5() {
        return String.format("%032x", random.nextLong() & Long.MAX_VALUE, random.nextLong() & Long.MAX_VALUE);
    }
    
    /**
     * 进程节点类
     */
    static class ProcessNode {
        String processGuid;
        String parentProcessGuid;
        String processName;
        int processId;
        int parentProcessId;
        int layer;
        String hostAddress;
        String productVendorName;
        String traceId;
    }
}







