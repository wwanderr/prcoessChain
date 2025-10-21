package com.security.processchain.service;

import java.util.HashMap;
import java.util.Map;

/**
 * 故事线节点
 */
public class StoryNode {
    private String type;
    private Map<String, Object> other;
    
    public StoryNode() {
        this.other = new HashMap<>();
    }
    
    public String getType() {
        return type;
    }
    
    public void setType(String type) {
        this.type = type;
    }
    
    public Map<String, Object> getOther() {
        return other;
    }
    
    public void setOther(Map<String, Object> other) {
        this.other = other;
    }
}



