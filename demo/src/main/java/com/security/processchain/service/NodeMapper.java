package com.security.processchain.service;

import com.security.processchain.model.ProcessNode;

/**
 * 节点映射器接口
 * 将 ProcessChainBuilder 的内部节点转换为最终返回的节点
 */
public interface NodeMapper {
    /**
     * 将 Builder 内部节点转换为对外返回的节点
     * 
     * @param builderNode Builder 内部节点
     * @return 最终返回节点
     */
    ProcessNode toIncidentNode(ProcessChainBuilder.ProcessNode builderNode);
}



