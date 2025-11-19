package com.security.processchain.util;

import com.security.processchain.service.GraphNode;
import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

/**
 * 日志节点拆分结果
 * 
 * 包含拆分后的节点和边信息：
 * - parentNode: 父进程节点（可能为虚拟节点）
 * - childNode: 子进程节点（必有）
 * - entityNode: 实体节点（file/domain/network/registry类型才有）
 * - edges: 节点间的边
 */
@Getter
@Setter
public class SplitResult {
    private GraphNode parentNode;
    private GraphNode childNode;
    private GraphNode entityNode;
    private List<EdgePair> edges;
    
    public SplitResult() {
        this.edges = new ArrayList<>();
    }
    
    /**
     * 添加边
     */
    public void addEdge(String source, String target) {
        edges.add(new EdgePair(source, target));
    }
}

