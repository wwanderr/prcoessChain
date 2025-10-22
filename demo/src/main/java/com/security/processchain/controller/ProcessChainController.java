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
import java.util.Map;

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
     * 为单个IP生成进程链
     * 
     * @param ip IP地址
     * @param associatedEventId 关联事件ID（可选）
     * @param hasAssociation 是否有网端关联（可选，默认false）
     * @return 进程链
     */
    @GetMapping("/generate")
    public IncidentProcessChain generateProcessChain(
            @RequestParam String ip,
            @RequestParam(required = false) String associatedEventId,
            @RequestParam(required = false, defaultValue = "false") Boolean hasAssociation) {
        
        log.info("收到单个IP进程链生成请求: ip={}, associatedEventId={}, hasAssociation={}", 
                ip, associatedEventId, hasAssociation);
        
        return processChainService.generateProcessChainForIp(ip, associatedEventId, hasAssociation);
    }

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

