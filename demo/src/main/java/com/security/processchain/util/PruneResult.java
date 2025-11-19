package com.security.processchain.util;

import lombok.Getter;

/**
 * 裁剪结果
 */
@Getter
public class PruneResult {
    private final int originalNodeCount;
    private final int removedNodeCount;
    private final int removedEdgeCount;
    private final int mustKeepCount;
    private final int cascadeKeepCount;
    
    public PruneResult(int originalNodeCount, int removedNodeCount, int removedEdgeCount,
                      int mustKeepCount, int cascadeKeepCount) {
        this.originalNodeCount = originalNodeCount;
        this.removedNodeCount = removedNodeCount;
        this.removedEdgeCount = removedEdgeCount;
        this.mustKeepCount = mustKeepCount;
        this.cascadeKeepCount = cascadeKeepCount;
    }
    
    public int getFinalNodeCount() {
        return originalNodeCount - removedNodeCount;
    }
}

