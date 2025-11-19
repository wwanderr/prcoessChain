package com.security.processchain.service;

import lombok.Getter;
import lombok.Setter;

/**
 * 进程边内部类
 */
@Getter
@Setter
public class ChainBuilderEdge {
    private String source;
    private String target;
    private String val;
}

