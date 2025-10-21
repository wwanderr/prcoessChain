package com.security.processchain.constants;

import java.util.Arrays;
import java.util.List;

/**
 * 进程链相关常量定义
 */
public final class ProcessChainConstants {

    private ProcessChainConstants() {
        // 工具类，防止实例化
    }

    /**
     * 时间相关常量
     */
    public static final class Time {
        private Time() {}
        
        /** 日期时间格式 */
        public static final String DATE_TIME_FORMAT = "yyyy-MM-dd HH:mm:ss";
        
        /** 默认时间窗口（小时） */
        public static final int DEFAULT_TIME_WINDOW_HOURS = 24;
    }

    /**
     * 日志类型常量
     */
    public static final class LogType {
        private LogType() {}
        
        /** 进程相关日志类型 */
        public static final String PROCESS = "process";
        public static final String PROCESS_CREATE = "进程创建";
        public static final String PROCESS_END = "进程结束";
        
        /** 文件相关日志类型 */
        public static final String FILE = "file";
        public static final String FILE_CREATE = "文件创建";
        public static final String FILE_MODIFY = "文件修改";
        public static final String FILE_DELETE = "文件删除";
        
        /** 网络相关日志类型 */
        public static final String NETWORK = "network";
        public static final String NETWORK_CONNECT = "网络连接";
        
        /** 域名相关日志类型 */
        public static final String DOMAIN = "domain";
        public static final String DOMAIN_RESOLVE = "域名解析";
        
        /** 注册表相关日志类型 */
        public static final String REGISTRY = "registry";
        public static final String REGISTRY_OPERATION = "注册表操作";
        
        /** 所有关注的日志类型列表 */
        public static final List<String> ALL_MONITORED_TYPES = Arrays.asList(
            PROCESS_CREATE, PROCESS_END,
            FILE_CREATE, FILE_MODIFY, FILE_DELETE,
            NETWORK_CONNECT,
            DOMAIN_RESOLVE,
            REGISTRY_OPERATION
        );
        
        /** Builder内部使用的日志类型列表 */
        public static final List<String> BUILDER_LOG_TYPES = Arrays.asList(
            PROCESS, FILE, NETWORK, DOMAIN
        );
    }

    /**
     * 告警相关常量
     */
    public static final class Alarm {
        private Alarm() {}
        
        /** 告警来源 */
        public static final String SOURCE_EDR = "EDR";
        
        /** 威胁等级 */
        public static final String SEVERITY_HIGH_CN = "高";
        public static final String SEVERITY_MEDIUM_CN = "中";
        public static final String SEVERITY_LOW_CN = "低";
        
        public static final String SEVERITY_HIGH_EN = "HIGH";
        public static final String SEVERITY_MEDIUM_EN = "MEDIUM";
        public static final String SEVERITY_LOW_EN = "LOW";
    }

    /**
     * 进程链构建限制
     */
    public static final class Limits {
        private Limits() {}
        
        /** 最大遍历深度 */
        public static final int MAX_TRAVERSE_DEPTH = 50;
        
        /** 最大节点数量 */
        public static final int MAX_NODE_COUNT = 400;
        
        /** 默认ES查询大小 */
        public static final int DEFAULT_ES_QUERY_SIZE = 10000;
    }

    /**
     * ES索引名称
     */
    public static final class ESIndex {
        private ESIndex() {}
        
        /** 默认告警索引名 */
        public static final String DEFAULT_ALARM_INDEX = "alarm_index";
        
        /** 默认日志索引名 */
        public static final String DEFAULT_LOG_INDEX = "log_index";
    }
}


