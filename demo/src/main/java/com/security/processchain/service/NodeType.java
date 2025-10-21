package com.security.processchain.service;

/**
 * 节点类型枚举
 */
public enum NodeType {
    PROCESS,   // 进程节点
    FILE,      // 文件节点
    NETWORK,   // 网络节点
    DOMAIN,    // 域名节点
    REGISTRY,  // 注册表节点
    EXPLORE,   // 探索节点（用于断裂链的占位节点）
    UNKNOWN    // 未知类型
}



