package com.security.processchain.model;

/**
 * 进程边（最终返回给前端的边结构）
 * 描述节点之间的关系
 */
public class ProcessEdge {
    /**
     * 源节点（进程链节点时用GUID，故事线节点用attacker等）
     */
    private String source;
    
    /**
     * 目标节点
     */
    private String target;
    
    /**
     * 连接描述（故事线连接的描述信息）
     */
    private String val;
    
    /**
     * 无参构造函数，val 默认为"连接"
     */
    public ProcessEdge() {
        this.val = "连接";
    }
    
    // Getters and Setters
    
    public String getSource() {
        return source;
    }
    
    public void setSource(String source) {
        this.source = source;
    }
    
    public String getTarget() {
        return target;
    }
    
    public void setTarget(String target) {
        this.target = target;
    }
    
    public String getVal() {
        return val;
    }
    
    public void setVal(String val) {
        this.val = val;
    }
}


