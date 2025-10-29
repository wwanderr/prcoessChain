import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * 时间戳更新工具
 * 专门用于更新demo/dataSet目录下的JSON文件中的时间字段
 */
public class UpdateTimestamps {
    
    // 写死的路径
    private static final String BASE_PATH = "demo/dataSet";
    private static final String[] TARGET_DIRS = {
        "webshell文件上传",
        "命令执行", 
        "矿池"
    };
    
    // 时间字段模式
    private static final String[] TIME_FIELDS = {
        "startTime", "endTime", "collectorReceiptTime", "deviceReceiptTime", 
        "@timestamp", "baas_sink_process_time", "eventTime", "createdTime", "processCreateTime"
    };
    
    private static final DateTimeFormatter STANDARD_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
    
    public static void main(String[] args) {
        System.out.println("============================================================");
        System.out.println("时间戳更新工具");
        System.out.println("============================================================");
        
        LocalDateTime currentTime = LocalDateTime.now();
        long currentTimestamp = System.currentTimeMillis();
        
        System.out.println("当前时间: " + currentTime.format(STANDARD_FORMATTER));
        System.out.println("当前时间戳: " + currentTimestamp);
        System.out.println("目标目录: " + BASE_PATH);
        System.out.println("------------------------------------------------------------");
        
        int totalFiles = 0;
        int updatedFiles = 0;
        
        // 遍历所有目标目录
        for (String targetDir : TARGET_DIRS) {
            String fullPath = BASE_PATH + "/" + targetDir;
            System.out.println("处理目录: " + fullPath);
            
            Path dirPath = Paths.get(fullPath);
            if (Files.exists(dirPath)) {
                int[] result = processDirectory(dirPath, currentTime, currentTimestamp);
                totalFiles += result[0];
                updatedFiles += result[1];
            } else {
                System.out.println("  目录不存在: " + fullPath);
            }
        }
        
        System.out.println("------------------------------------------------------------");
        System.out.println("更新完成: 共处理 " + totalFiles + " 个文件，更新 " + updatedFiles + " 个文件");
        System.out.println("============================================================");
    }
    
    /**
     * 递归处理目录中的所有JSON文件
     */
    private static int[] processDirectory(Path dir, LocalDateTime currentTime, long currentTimestamp) {
        int totalFiles = 0;
        int updatedFiles = 0;
        
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
            for (Path path : stream) {
                if (Files.isDirectory(path)) {
                    // 递归处理子目录
                    int[] subResult = processDirectory(path, currentTime, currentTimestamp);
                    totalFiles += subResult[0];
                    updatedFiles += subResult[1];
                } else if (path.toString().endsWith(".json")) {
                    // 处理JSON文件
                    totalFiles++;
                    System.out.println("  处理文件: " + dir.relativize(path));
                    
                    if (updateJsonFile(path, currentTime, currentTimestamp)) {
                        updatedFiles++;
                        System.out.println("    ✓ 已更新");
                    } else {
                        System.out.println("    - 无需更新");
                    }
                }
            }
        } catch (IOException e) {
            System.err.println("  处理目录失败: " + dir + " - " + e.getMessage());
        }
        
        return new int[]{totalFiles, updatedFiles};
    }
    
    /**
     * 更新单个JSON文件
     */
    private static boolean updateJsonFile(Path filePath, LocalDateTime currentTime, long currentTimestamp) {
        try {
            // 读取文件内容
            String content = Files.readString(filePath, StandardCharsets.UTF_8);
            String originalContent = content;
            
            // 更新各种时间字段
            for (String field : TIME_FIELDS) {
                content = updateTimeField(content, field, currentTime, currentTimestamp);
            }
            
            // 如果内容有变化，写回文件
            if (!content.equals(originalContent)) {
                Files.writeString(filePath, content, StandardCharsets.UTF_8);
                return true;
            }
            
            return false;
            
        } catch (IOException e) {
            System.err.println("    更新失败: " + filePath + " - " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 更新特定时间字段
     */
    private static String updateTimeField(String content, String fieldName, LocalDateTime currentTime, long currentTimestamp) {
        String pattern;
        String replacement;
        
        if (fieldName.equals("@timestamp")) {
            // ISO格式时间戳
            pattern = "\"@timestamp\":\\s*\"([^\"]+)\"";
            replacement = "\"@timestamp\": \"" + currentTime.format(ISO_FORMATTER) + "\"";
        } else if (fieldName.equals("baas_sink_process_time") || fieldName.equals("eventTime")) {
            // 时间戳字段（数字）
            pattern = "\"" + fieldName + "\":\\s*(\\d+)";
            replacement = "\"" + fieldName + "\": " + currentTimestamp;
        } else if (fieldName.equals("createdTime") || fieldName.equals("processCreateTime")) {
            // 时间戳字段（字符串）
            pattern = "\"" + fieldName + "\":\\s*\"(\\d+)\"";
            replacement = "\"" + fieldName + "\": \"" + currentTimestamp + "\"";
        } else {
            // 标准时间格式字段
            pattern = "\"" + fieldName + "\":\\s*\"([^\"]+)\"";
            replacement = "\"" + fieldName + "\": \"" + currentTime.format(STANDARD_FORMATTER) + "\"";
        }
        
        return content.replaceAll(pattern, replacement);
    }
}
