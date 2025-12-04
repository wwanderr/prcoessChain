package com.security.processchain.model;

import lombok.Data;
import java.util.ArrayList;
import java.util.List;

/**
 * 风险事件信息
 * 用于网侧和端侧桥接时的角色识别
 */
@Data
public class RiskIncident {
    /**
     * 焦点 IP 列表（逗号分隔的字符串）
     * 例如: "10.20.152.227,10.50.24.4,10.20.152.228"
     */
    private String focusIp;
    
    /**
     * 焦点对象角色（"attacker" 或 "victim"）
     */
    private String focusObject;
    
    /**
     * 获取焦点 IP 列表（解析后）
     * 
     * @return IP 列表（已 trim）
     */
    public List<String> getFocusIpList() {
        if (focusIp == null || focusIp.trim().isEmpty()) {
            return new ArrayList<>();
        }
        
        String[] ips = focusIp.split(",");
        List<String> result = new ArrayList<>();
        for (String ip : ips) {
            String trimmed = ip.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }
}

