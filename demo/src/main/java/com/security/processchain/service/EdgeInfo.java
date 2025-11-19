package com.security.processchain.service;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

/**
 * 边信息
 * 
 * 表示进程链图中一条边的属性信息
 */
@Getter
@Setter
@AllArgsConstructor
public class EdgeInfo {
    private String label;
    private String edgeType;
}
