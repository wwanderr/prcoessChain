package com.security.processchain.service;

import lombok.Getter;
import lombok.Setter;

/**
 * 进程链构建器内部使用的边结构
 * 包含 source、target 和 val（边的值，如"断链"）
 */
@Getter
@Setter
public class ChainBuilderEdge {
    private String source;
    private String target;
    
    /**
     * 边的值（如"断链"、"连接"）
     * null 表示普通边
     */
    private String val;
}


