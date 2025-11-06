package com.security.processchain.service;

/**
 * 注册表实体
 */
public class RegistryEntity {
    private String targetObject;
    private String regValue;
    private String targetObjectName;  // targetObject 路径的最后一层
    
    public RegistryEntity() {
        this.targetObject = "";
        this.regValue = "";
        this.targetObjectName = "";
    }
    
    public String getTargetObject() {
        return targetObject;
    }
    
    public void setTargetObject(String targetObject) {
        this.targetObject = targetObject;
    }
    
    public String getRegValue() {
        return regValue;
    }
    
    public void setRegValue(String regValue) {
        this.regValue = regValue;
    }
    
    public String getTargetObjectName() {
        return targetObjectName;
    }
    
    public void setTargetObjectName(String targetObjectName) {
        this.targetObjectName = targetObjectName;
    }
}





