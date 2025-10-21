package com.security.processchain.service;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;

import java.util.List;

/**
 * ES查询服务接口
 * 需要根据实际ES客户端实现
 */
public interface ESQueryService {
    
    /**
     * 查询EDR告警
     * 
     * @param hostAddress 主机地址
     * @return 告警列表
     */
    List<RawAlarm> queryEDRAlarms(String hostAddress);
    
    /**
     * 查询原始日志
     * 
     * @param traceId 溯源ID
     * @param hostAddress 主机地址
     * @param timeStart 开始时间
     * @param timeEnd 结束时间
     * @param logTypes 日志类型列表
     * @return 日志列表
     */
    List<RawLog> queryRawLogs(String traceId, String hostAddress, String timeStart, String timeEnd, List<String> logTypes);
}



