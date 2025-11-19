package com.security.processchain.util;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * 边对
 * 
 * 表示进程链图中的一条有向边
 */
@Getter
@AllArgsConstructor
public class EdgePair {
    private String source;  // 源节点ID
    private String target;  // 目标节点ID
}

