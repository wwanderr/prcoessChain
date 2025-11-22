package com.security.processchain.service;

import lombok.Getter;
import lombok.Setter;

/**
 * 进程链构建器内部使用的边结构（简化版）
 * 只包含 source 和 target，不包含其他属性
 */
@Getter
@Setter
public class ChainBuilderEdge {
    private String source;
    private String target;
}


