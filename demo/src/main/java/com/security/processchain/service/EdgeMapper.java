package com.security.processchain.service;

import com.security.processchain.model.ProcessEdge;

/**
 * 边映射器接口
 * 将 ProcessChainBuilder 的内部边转换为最终返回的边
 */
public interface EdgeMapper {
    /**
     * 将 Builder 内部边转换为对外返回的边
     * 
     * @param builderEdge Builder 内部边
     * @return 最终返回边
     */
    ProcessEdge toIncidentEdge(ProcessChainBuilder.ChainBuilderEdge builderEdge);
}



