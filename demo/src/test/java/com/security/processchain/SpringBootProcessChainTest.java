package com.security.processchain;

import com.security.processchain.model.IncidentProcessChain;
import com.security.processchain.service.impl.ProcessChainServiceImpl;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.*;

/**
 * SpringBoot集成测试
 * 测试进程链生成的完整流程
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class SpringBootProcessChainTest {

    @Autowired
    private ProcessChainServiceImpl processChainService;

    /**
     * 测试单个IP生成进程链
     */
    @Test
    public void testSingleIpProcessChain() {
        System.out.println("\n========== 测试单个IP生成进程链 ==========");
        
        String ip = "192.168.1.100";
        String associatedEventId = "event_001";
        
        IncidentProcessChain chain = processChainService.generateProcessChainForIp(ip, associatedEventId);
        
        if (chain != null) {
            System.out.println("进程链生成成功!");
            System.out.println("事件ID: " + chain.getIncidentId());
            System.out.println("节点数: " + (chain.getNodes() != null ? chain.getNodes().size() : 0));
            System.out.println("边数: " + (chain.getEdges() != null ? chain.getEdges().size() : 0));
        } else {
            System.out.println("进程链生成失败（可能ES中没有数据）");
        }
    }

    /**
     * 测试批量生成进程链
     */
    @Test
    public void testBatchProcessChain() {
        System.out.println("\n========== 测试批量生成进程链 ==========");
        
        // 准备测试数据
        List<String> ips = Arrays.asList(
            "192.168.1.100",
            "192.168.1.101",
            "192.168.1.102",
            "192.168.1.103",
            "192.168.1.104"
        );
        
        Map<String, String> associatedEventIds = new HashMap<>();
        associatedEventIds.put("192.168.1.100", "event_001");
        associatedEventIds.put("192.168.1.101", "event_002");
        
        // 执行批量生成
        long startTime = System.currentTimeMillis();
        Map<String, IncidentProcessChain> results = processChainService.generateProcessChains(ips, associatedEventIds);
        long endTime = System.currentTimeMillis();
        
        // 输出结果
        System.out.println("\n批量生成完成，总耗时: " + (endTime - startTime) + "ms");
        System.out.println("成功生成: " + results.size() + "/" + ips.size());
        
        for (Map.Entry<String, IncidentProcessChain> entry : results.entrySet()) {
            String ip = entry.getKey();
            IncidentProcessChain chain = entry.getValue();
            System.out.println("\nIP: " + ip);
            System.out.println("  事件ID: " + chain.getIncidentId());
            System.out.println("  节点数: " + (chain.getNodes() != null ? chain.getNodes().size() : 0));
            System.out.println("  边数: " + (chain.getEdges() != null ? chain.getEdges().size() : 0));
        }
    }

    /**
     * 测试批量查询性能对比
     */
    @Test
    public void testBatchQueryPerformance() {
        System.out.println("\n========== 测试批量查询性能 ==========");
        
        List<String> ips = new ArrayList<>();
        for (int i = 1; i <= 10; i++) {
            ips.add("192.168.1." + (100 + i));
        }
        
        System.out.println("测试IP数量: " + ips.size());
        
        // 批量查询
        long batchStart = System.currentTimeMillis();
        Map<String, IncidentProcessChain> batchResults = processChainService.generateProcessChains(ips, null);
        long batchEnd = System.currentTimeMillis();
        long batchTime = batchEnd - batchStart;
        
        System.out.println("\n批量查询结果:");
        System.out.println("  耗时: " + batchTime + "ms");
        System.out.println("  成功: " + batchResults.size());
        System.out.println("  平均每个IP: " + (batchResults.isEmpty() ? 0 : batchTime / batchResults.size()) + "ms");
        
        // 说明：如果要对比串行查询，可以循环调用generateProcessChainForIp
        // 但批量查询应该快得多，特别是在网络延迟较高的情况下
    }
}

