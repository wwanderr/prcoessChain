package com.security.processchain.service;

import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

/**
 * 故事线节点
 */
@Getter
public class StoryNode {
    private String type;
    private Map<String, Object> node;
    
    public StoryNode() {
        this.node = new HashMap<>();
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setNode(Map<String, Object> node) {
        this.node = node;
    }
}



