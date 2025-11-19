package com.security.processchain.service;

/**
 * 节点颜色（用于DFS环检测）
 * 
 * 在DFS遍历过程中，使用三种颜色标记节点的状态：
 * - WHITE: 未访问
 * - GRAY: 正在访问（在当前DFS路径中）
 * - BLACK: 已完成访问
 */
enum NodeColor {
    WHITE,  // 未访问
    GRAY,   // 正在访问
    BLACK   // 已完成
}

