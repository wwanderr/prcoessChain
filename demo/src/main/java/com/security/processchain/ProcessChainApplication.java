package com.security.processchain;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * 进程链生成系统 - SpringBoot启动类
 * 
 * @author Security Team
 * @version 1.0.0
 */
@SpringBootApplication
public class ProcessChainApplication {

    public static void main(String[] args) {
        SpringApplication.run(ProcessChainApplication.class, args);
        System.out.println("========================================");
        System.out.println("进程链生成系统启动成功！");
        System.out.println("========================================");
    }
}

