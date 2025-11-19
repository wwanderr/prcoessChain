package com.security.processchain.util;

import com.security.processchain.service.ChainBuilderEdge;
import com.security.processchain.service.ChainBuilderNode;
import lombok.Getter;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 裁剪上下文 - 封装裁剪所需的所有数据
 */
@Getter
public class PruneContext {
    private final Map<String, ChainBuilderNode> nodeMap;
    private final List<ChainBuilderEdge> edges;
    private final Set<String> rootNodes;
    private final Set<String> associatedEventIds;
    
    public PruneContext(Map<String, ChainBuilderNode> nodeMap,
                      List<ChainBuilderEdge> edges,
                      Set<String> rootNodes,
                      Set<String> associatedEventIds) {
        // 防御性检查
        if (nodeMap == null) {
            throw new IllegalArgumentException("nodeMap cannot be null");
        }
        if (edges == null) {
            throw new IllegalArgumentException("edges cannot be null");
        }
        if (rootNodes == null) {
            throw new IllegalArgumentException("rootNodes cannot be null");
        }
        
        this.nodeMap = nodeMap;
        this.edges = edges;
        this.rootNodes = rootNodes;
        this.associatedEventIds = (associatedEventIds != null) ? associatedEventIds : new HashSet<>();
    }
}

