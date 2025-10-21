package com.security.processchain.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * 进程链配置类
 */
@Configuration
@ConfigurationProperties(prefix = "process-chain")
public class ProcessChainConfig {

    /**
     * 告警索引名称
     */
    private String alarmIndex = "alarm_index";

    /**
     * 日志索引名称
     */
    private String logIndex = "log_index";

    /**
     * 最大遍历深度
     */
    private int maxTraversalDepth = 50;

    /**
     * 最大节点数
     */
    private int maxNodeCount = 400;

    /**
     * 批量查询大小
     */
    private int batchQuerySize = 100;

    /**
     * ES查询最大返回数
     */
    private int maxQuerySize = 10000;

    // Getters and Setters
    public String getAlarmIndex() {
        return alarmIndex;
    }

    public void setAlarmIndex(String alarmIndex) {
        this.alarmIndex = alarmIndex;
    }

    public String getLogIndex() {
        return logIndex;
    }

    public void setLogIndex(String logIndex) {
        this.logIndex = logIndex;
    }

    public int getMaxTraversalDepth() {
        return maxTraversalDepth;
    }

    public void setMaxTraversalDepth(int maxTraversalDepth) {
        this.maxTraversalDepth = maxTraversalDepth;
    }

    public int getMaxNodeCount() {
        return maxNodeCount;
    }

    public void setMaxNodeCount(int maxNodeCount) {
        this.maxNodeCount = maxNodeCount;
    }

    public int getBatchQuerySize() {
        return batchQuerySize;
    }

    public void setBatchQuerySize(int batchQuerySize) {
        this.batchQuerySize = batchQuerySize;
    }

    public int getMaxQuerySize() {
        return maxQuerySize;
    }

    public void setMaxQuerySize(int maxQuerySize) {
        this.maxQuerySize = maxQuerySize;
    }
}
