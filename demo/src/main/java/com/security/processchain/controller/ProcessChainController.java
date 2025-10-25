package com.security.processchain.controller;

import com.security.processchain.model.IpMappingRelation;
import com.security.processchain.model.ProcessEdge;
import com.security.processchain.model.ProcessNode;
import com.security.processchain.service.IncidentProcessChain;
import com.security.processchain.service.impl.ProcessChainServiceImpl;
import com.security.processchain.util.Pair;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 进程链生成REST API控制器
 */
@Slf4j
@RestController
@RequestMapping("/api/processchain")
public class ProcessChainController {

    @Autowired
    private ProcessChainServiceImpl processChainService;


    /**
     * 批量生成进程链（端侧）
     * 使用IpMappingRelation数据结构
     * 所有IP的进程链合并到一个IncidentProcessChain中
     * 
     * @param ipMappingRelation IP映射关系
     * @return 合并后的进程链
     */
    @PostMapping("/batch-generate")
    public IncidentProcessChain batchGenerateProcessChains(
            @RequestBody IpMappingRelation ipMappingRelation) {
        
        log.info("收到批量进程链生成请求（仅端侧）: {}", ipMappingRelation);
        
        // 输入验证
        if (ipMappingRelation == null) {
            log.error("【输入验证失败】-> IpMappingRelation参数为空");
            return null;
        }
        
        if (ipMappingRelation.getIpAndAssociation() == null || ipMappingRelation.getIpAndAssociation().isEmpty()) {
            log.error("【输入验证失败】-> IP列表为空");
            return null;
        }
        
        return processChainService.generateProcessChains(ipMappingRelation, null);
    }

    /**
     * 合并网侧和端侧进程链
     * 
     * @param request 合并请求（包含网侧节点边和端侧IpMappingRelation）
     * @return 合并后的完整进程链
     */
    @PostMapping("/merge-chain")
    public IncidentProcessChain mergeNetworkAndEndpointChain(
            @RequestBody MergeChainRequest request) {
        
        log.info("收到合并进程链请求");
        
        // 输入验证
        if (request == null) {
            log.error("【输入验证失败】-> 合并请求为空");
            return null;
        }
        
        if (request.getIpMappingRelation() == null) {
            log.error("【输入验证失败】-> IpMappingRelation参数为空");
            return null;
        }
        
        // 封装网侧数据为 Pair
        Pair<List<ProcessNode>, List<ProcessEdge>> networkChain = null;
        if (request.getNetworkNodes() != null || request.getNetworkEdges() != null) {
            networkChain = Pair.of(request.getNetworkNodes(), request.getNetworkEdges());
        }
        
        // 调用 Service 生成并合并进程链
        return processChainService.generateProcessChains(
            request.getIpMappingRelation(),
            networkChain
        );
    }
    
//    /**
//     * 健康检查
//     */
//    @GetMapping("/health")
//    public Map<String, String> health() {
//        log.debug("健康检查请求");
//        return Map.of(
//            "status", "UP",
//            "service", "Process Chain Generator"
//        );
//    }
    
    /**
     * 合并进程链请求对象
     */
    public static class MergeChainRequest {
        private List<ProcessNode> networkNodes;
        private List<ProcessEdge> networkEdges;
        private IpMappingRelation ipMappingRelation;

        public List<ProcessNode> getNetworkNodes() {
            return networkNodes;
        }

        public void setNetworkNodes(List<ProcessNode> networkNodes) {
            this.networkNodes = networkNodes;
        }

        public List<ProcessEdge> getNetworkEdges() {
            return networkEdges;
        }

        public void setNetworkEdges(List<ProcessEdge> networkEdges) {
            this.networkEdges = networkEdges;
        }

        public IpMappingRelation getIpMappingRelation() {
            return ipMappingRelation;
        }

        public void setIpMappingRelation(IpMappingRelation ipMappingRelation) {
            this.ipMappingRelation = ipMappingRelation;
        }
    }
}

