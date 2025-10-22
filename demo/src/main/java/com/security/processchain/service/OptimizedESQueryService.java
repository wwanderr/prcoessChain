package com.security.processchain.service;

import com.security.processchain.model.RawAlarm;
import com.security.processchain.model.RawLog;
import com.security.processchain.util.DataConverter;
import lombok.extern.slf4j.Slf4j;
import org.elasticsearch.action.search.MultiSearchRequest;
import org.elasticsearch.action.search.MultiSearchResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.*;

/**
 * 优化的ES查询服务实现
 * 使用RestHighLevelClient，通过批量查询和聚合查询减少ES查询次数
 * 
 * 性能优化策略：
 * 1. 批量查询：使用MultiSearchRequest一次性查询多个IP的告警
 * 2. 批量日志查询：一次性查询多个traceId的日志
 * 3. 合理设置查询大小，避免分页查询
 */
@Slf4j
@Service("optimizedESQueryService")
public class OptimizedESQueryService implements ESQueryService {

    @Autowired
    private RestHighLevelClient esClient;

    @Value("${process-chain.alarm-index:alarm_index}")
    private String alarmIndex;

    @Value("${process-chain.log-index:log_index}")
    private String logIndex;

    @Value("${process-chain.max-query-size:10000}")
    private int maxQuerySize;

    /**
     * 告警查询需要的字段（减少网络传输，提升查询性能）
     */
    private static final String[] ALARM_INCLUDES = new String[]{
        "eventId",
        "traceId",
        "hostAddress",
        "processGuid",
        "parentProcessGuid",
        "alarmName",
        "threatSeverity",
        "startTime",
        "endTime",
        "alarmSource",
        "logType",
        "otherFields"
    };

    /**
     * 日志查询需要的字段（减少网络传输，提升查询性能）
     */
    private static final String[] LOG_INCLUDES = new String[]{
        "traceId",
        "hostAddress",
        "processGuid",
        "parentProcessGuid",
        "logType",
        "eventType",
        "opType",
        "startTime",
        "endTime",
        "processName",
        "processPath",
        "commandLine",
        "fileName",
        "filePath",
        "fileSize",
        "targetFilename",
        "fileMd5",
        "fileType",
        "sourceIp",
        "sourcePort",
        "destIp",
        "destPort",
        "domainName",
        "requestDomain",
        "queryResults",
        "targetObject",
        "regValue",
        "otherFields"
    };

    /**
     * 批量查询多个IP的EDR告警
     * 优化：使用MultiSearchRequest一次性查询多个IP，减少网络往返次数
     * 
     * @param hostAddresses IP地址列表
     * @return IP到告警列表的映射
     */
    public Map<String, List<RawAlarm>> batchQueryEDRAlarms(List<String> hostAddresses) {
        if (hostAddresses == null || hostAddresses.isEmpty()) {
            log.error("hostAddresses为空");
            return new HashMap<>();
        }

        Map<String, List<RawAlarm>> resultMap = new HashMap<>();

        try {
            log.info("批量查询EDR告警: IP数量={}", hostAddresses.size());

            // 创建MultiSearchRequest
            MultiSearchRequest multiSearchRequest = new MultiSearchRequest();

            // 为每个IP创建一个SearchRequest
            for (String hostAddress : hostAddresses) {
                if (hostAddress == null || hostAddress.trim().isEmpty()) {
                    continue;
                }

                SearchRequest searchRequest = new SearchRequest(alarmIndex);
                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();

                // 构建查询条件（使用filter，不计算评分，可缓存）
                BoolQueryBuilder boolQuery = QueryBuilders.boolQuery();
                boolQuery.filter(QueryBuilders.termQuery("hostAddress", hostAddress));
                boolQuery.filter(QueryBuilders.termQuery("alarmSource", "EDR"));

                searchSourceBuilder.query(boolQuery);
                searchSourceBuilder.size(maxQuerySize);
                searchSourceBuilder.fetchSource(ALARM_INCLUDES, null);  // 只返回需要的字段
                searchRequest.source(searchSourceBuilder);

                multiSearchRequest.add(searchRequest);
            }

            // 执行批量查询
            long startTime = System.currentTimeMillis();
            MultiSearchResponse multiSearchResponse = esClient.msearch(multiSearchRequest, RequestOptions.DEFAULT);
            long endTime = System.currentTimeMillis();

            log.info("批量查询完成，耗时: {}ms", (endTime - startTime));

            // 处理每个IP的查询结果
            MultiSearchResponse.Item[] responses = multiSearchResponse.getResponses();
            for (int i = 0; i < responses.length && i < hostAddresses.size(); i++) {
                String hostAddress = hostAddresses.get(i);
                MultiSearchResponse.Item item = responses[i];

                if (item.isFailure()) {
                    log.error("查询失败 [{}]: {}", hostAddress, item.getFailureMessage());
                    resultMap.put(hostAddress, new ArrayList<>());
                    continue;
                }

                SearchResponse searchResponse = item.getResponse();
                List<Map<String, Object>> hitMaps = extractHits(searchResponse);
                List<RawAlarm> alarms = DataConverter.convertToAlarmList(hitMaps);

                resultMap.put(hostAddress, alarms);
                log.debug("IP [{}] 查询到告警数: {}", hostAddress, alarms.size());
            }

            return resultMap;

        } catch (IOException e) {
            log.error("批量查询EDR告警失败: {}", e.getMessage(), e);
            return resultMap;
        }
    }

    /**
     * 批量查询多个traceId的原始日志（简化版本，用于ProcessChainServiceImpl）
     * 优化：使用MultiSearchRequest为每个traceId单独查询，与告警查询方式统一
     * 
     * @param traceIds traceId列表
     * @param hostAddress 主机地址
     * @return 所有日志的列表（不分组）
     */
    public List<RawLog> batchQueryRawLogs(List<String> traceIds, String hostAddress) {
        if (traceIds == null || traceIds.isEmpty() || hostAddress == null) {
            log.error("traceIds或hostAddress为空");
            return new ArrayList<>();
        }

        List<RawLog> allLogs = new ArrayList<>();

        try {
            log.info("批量查询原始日志: traceId数量={}, hostAddress={}", traceIds.size(), hostAddress);

            // 创建MultiSearchRequest
            MultiSearchRequest multiSearchRequest = new MultiSearchRequest();

            // 为每个traceId创建一个SearchRequest
            for (String traceId : traceIds) {
                if (traceId == null || traceId.trim().isEmpty()) {
                    continue;
                }

                SearchRequest searchRequest = new SearchRequest(logIndex);
                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();

                // 构建查询条件（使用filter，不计算评分，可缓存）
                BoolQueryBuilder boolQuery = QueryBuilders.boolQuery();
                boolQuery.filter(QueryBuilders.termQuery("traceId", traceId));
                boolQuery.filter(QueryBuilders.termQuery("hostAddress", hostAddress));

                searchSourceBuilder.query(boolQuery);
                searchSourceBuilder.size(maxQuerySize);
                searchSourceBuilder.fetchSource(LOG_INCLUDES, null);  // 只返回需要的字段
                searchRequest.source(searchSourceBuilder);

                multiSearchRequest.add(searchRequest);
            }

            // 执行批量查询
            long startTime = System.currentTimeMillis();
            MultiSearchResponse multiSearchResponse = esClient.msearch(multiSearchRequest, RequestOptions.DEFAULT);
            long endTime = System.currentTimeMillis();

            log.info("批量日志查询完成，耗时: {}ms", (endTime - startTime));

            // 处理每个traceId的查询结果
            MultiSearchResponse.Item[] responses = multiSearchResponse.getResponses();
            for (int i = 0; i < responses.length && i < traceIds.size(); i++) {
                String traceId = traceIds.get(i);
                MultiSearchResponse.Item item = responses[i];

                if (item.isFailure()) {
                    log.error("查询失败 [{}]: {}", traceId, item.getFailureMessage());
                    continue;
                }

                SearchResponse searchResponse = item.getResponse();
                List<Map<String, Object>> hitMaps = extractHits(searchResponse);
                List<RawLog> logs = DataConverter.convertToLogList(hitMaps);

                allLogs.addAll(logs);
                log.debug("traceId [{}] 查询到日志数: {}", traceId, logs.size());
            }

            log.info("查询到日志总数: {}", allLogs.size());
            return allLogs;

        } catch (IOException e) {
            log.error("批量查询原始日志失败: {}", e.getMessage(), e);
            return allLogs;
        }
    }

    /**
     * 批量查询多个traceId的原始日志（完整版本，支持时间和类型过滤）
     * 优化：使用MultiSearchRequest为每个traceId单独查询，与告警查询方式统一
     * 
     * @param traceIds traceId列表
     * @param hostAddress 主机地址
     * @param timeStart 时间范围开始
     * @param timeEnd 时间范围结束
     * @param logTypes 日志类型列表
     * @return traceId到日志列表的映射
     */
    public Map<String, List<RawLog>> batchQueryRawLogs(List<String> traceIds, String hostAddress,
                                                        String timeStart, String timeEnd, List<String> logTypes) {
        if (traceIds == null || traceIds.isEmpty() || hostAddress == null) {
            log.error("traceIds或hostAddress为空");
            return new HashMap<>();
        }

        Map<String, List<RawLog>> resultMap = new HashMap<>();

        try {
            log.info("批量查询原始日志: traceId数量={}, hostAddress={}", traceIds.size(), hostAddress);

            // 创建MultiSearchRequest
            MultiSearchRequest multiSearchRequest = new MultiSearchRequest();

            // 为每个traceId创建一个SearchRequest
            for (String traceId : traceIds) {
                if (traceId == null || traceId.trim().isEmpty()) {
                    continue;
                }

                SearchRequest searchRequest = new SearchRequest(logIndex);
                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();

                // 构建查询条件（使用filter，不计算评分，可缓存）
                BoolQueryBuilder boolQuery = QueryBuilders.boolQuery();
                boolQuery.filter(QueryBuilders.termQuery("traceId", traceId));
                boolQuery.filter(QueryBuilders.termQuery("hostAddress", hostAddress));

                // 时间范围查询
                if (timeStart != null && timeEnd != null) {
                    boolQuery.filter(QueryBuilders.rangeQuery("startTime")
                        .gte(timeStart)
                        .lte(timeEnd));
                }

                // 日志类型过滤
                if (logTypes != null && !logTypes.isEmpty()) {
                    boolQuery.filter(QueryBuilders.termsQuery("logType", logTypes));
                }

                searchSourceBuilder.query(boolQuery);
                searchSourceBuilder.size(maxQuerySize);
                searchSourceBuilder.fetchSource(LOG_INCLUDES, null);  // 只返回需要的字段
                searchRequest.source(searchSourceBuilder);

                multiSearchRequest.add(searchRequest);
            }

            // 执行批量查询
            long startTime = System.currentTimeMillis();
            MultiSearchResponse multiSearchResponse = esClient.msearch(multiSearchRequest, RequestOptions.DEFAULT);
            long endTime = System.currentTimeMillis();

            log.info("批量日志查询完成，耗时: {}ms", (endTime - startTime));

            // 处理每个traceId的查询结果
            MultiSearchResponse.Item[] responses = multiSearchResponse.getResponses();
            for (int i = 0; i < responses.length && i < traceIds.size(); i++) {
                String traceId = traceIds.get(i);
                MultiSearchResponse.Item item = responses[i];

                if (item.isFailure()) {
                    log.error("查询失败 [{}]: {}", traceId, item.getFailureMessage());
                    resultMap.put(traceId, new ArrayList<>());
                    continue;
                }

                SearchResponse searchResponse = item.getResponse();
                List<Map<String, Object>> hitMaps = extractHits(searchResponse);
                List<RawLog> logs = DataConverter.convertToLogList(hitMaps);

                resultMap.put(traceId, logs);
                log.debug("traceId [{}] 查询到日志数: {}", traceId, logs.size());
            }

            // 为没有日志的traceId添加空列表
            for (String traceId : traceIds) {
                resultMap.putIfAbsent(traceId, new ArrayList<>());
            }

            return resultMap;

        } catch (IOException e) {
            log.error("批量查询原始日志失败: {}", e.getMessage(), e);
            return resultMap;
        }
    }

    /**
     * 批量查询日志：输入为 hostAddress -> traceId 的映射
     * 每个映射项生成一个查询请求，统一通过 MultiSearchRequest 执行
     * 返回所有匹配日志的聚合列表
     */
    public List<RawLog> batchQueryRawLogs(Map<String, String> hostToTraceId) {
        if (hostToTraceId == null || hostToTraceId.isEmpty()) {
            log.error("hostToTraceId映射为空");
            return new ArrayList<>();
        }

        List<RawLog> allLogs = new ArrayList<>();

        try {
            log.info("批量查询原始日志: 映射数量={}", hostToTraceId.size());

            MultiSearchRequest multiSearchRequest = new MultiSearchRequest();

            for (Map.Entry<String, String> entry : hostToTraceId.entrySet()) {
                String hostAddress = entry.getKey();
                String traceId = entry.getValue();
                if (hostAddress == null || hostAddress.trim().isEmpty() ||
                    traceId == null || traceId.trim().isEmpty()) {
                    continue;
                }

                SearchRequest searchRequest = new SearchRequest(logIndex);
                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();

                BoolQueryBuilder boolQuery = QueryBuilders.boolQuery();
                boolQuery.filter(QueryBuilders.termQuery("traceId", traceId));
                boolQuery.filter(QueryBuilders.termQuery("hostAddress", hostAddress));

                searchSourceBuilder.query(boolQuery);
                searchSourceBuilder.size(maxQuerySize);
                searchSourceBuilder.fetchSource(LOG_INCLUDES, null);  // 只返回需要的字段
                searchRequest.source(searchSourceBuilder);

                multiSearchRequest.add(searchRequest);
            }

            long startTime = System.currentTimeMillis();
            MultiSearchResponse multiSearchResponse = esClient.msearch(multiSearchRequest, RequestOptions.DEFAULT);
            long endTime = System.currentTimeMillis();
            log.info("批量日志查询完成，耗时: {}ms", (endTime - startTime));

            MultiSearchResponse.Item[] responses = multiSearchResponse.getResponses();
            for (MultiSearchResponse.Item item : responses) {
                if (item.isFailure()) {
                    log.error("批量日志查询子请求失败: {}", item.getFailureMessage());
                    continue;
                }
                SearchResponse searchResponse = item.getResponse();
                List<Map<String, Object>> hitMaps = extractHits(searchResponse);
                List<RawLog> logs = DataConverter.convertToLogList(hitMaps);
                allLogs.addAll(logs);
            }

            log.info("批量日志查询总数: {}", allLogs.size());
            return allLogs;

        } catch (IOException e) {
            log.error("批量查询原始日志失败: {}", e.getMessage(), e);
            return allLogs;
        }
    }

    /**
     * 单个IP查询EDR告警（实现ESQueryService接口）
     */
    @Override
    public List<RawAlarm> queryEDRAlarms(String hostAddress) {
        if (hostAddress == null || hostAddress.trim().isEmpty()) {
            log.error("hostAddress为空");
            return new ArrayList<>();
        }

        try {
            log.debug("查询EDR告警: hostAddress={}", hostAddress);

            SearchRequest searchRequest = new SearchRequest(alarmIndex);
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();

            // 构建查询条件（使用filter，不计算评分，可缓存）
            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery();
            boolQuery.filter(QueryBuilders.termQuery("hostAddress", hostAddress));
            boolQuery.filter(QueryBuilders.termQuery("alarmSource", "EDR"));

            searchSourceBuilder.query(boolQuery);
            searchSourceBuilder.size(maxQuerySize);
            searchSourceBuilder.fetchSource(ALARM_INCLUDES, null);  // 只返回需要的字段
            searchRequest.source(searchSourceBuilder);

            // 执行查询
            SearchResponse searchResponse = esClient.search(searchRequest, RequestOptions.DEFAULT);

            // 提取hits并转换
            List<Map<String, Object>> hitMaps = extractHits(searchResponse);
            List<RawAlarm> alarms = DataConverter.convertToAlarmList(hitMaps);

            log.debug("查询到告警数: {}", alarms.size());
            return alarms;

        } catch (IOException e) {
            log.error("查询EDR告警失败: {}", e.getMessage(), e);
            return new ArrayList<>();
        }
    }

    /**
     * 单个traceId查询原始日志（实现ESQueryService接口）
     */
    @Override
    public List<RawLog> queryRawLogs(String traceId, String hostAddress,
                                     String timeStart, String timeEnd, List<String> logTypes) {
        if (traceId == null || hostAddress == null) {
            log.error("traceId或hostAddress为空");
            return new ArrayList<>();
        }

        try {
            log.debug("查询原始日志: traceId={}, hostAddress={}", traceId, hostAddress);

            SearchRequest searchRequest = new SearchRequest(logIndex);
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();

            // 构建查询条件（使用filter，不计算评分，可缓存）
            BoolQueryBuilder boolQuery = QueryBuilders.boolQuery();
            boolQuery.filter(QueryBuilders.termQuery("traceId", traceId));
            boolQuery.filter(QueryBuilders.termQuery("hostAddress", hostAddress));

            // 时间范围查询
            if (timeStart != null && timeEnd != null) {
                boolQuery.filter(QueryBuilders.rangeQuery("startTime")
                    .gte(timeStart)
                    .lte(timeEnd));
            }

            // 日志类型过滤
            if (logTypes != null && !logTypes.isEmpty()) {
                boolQuery.filter(QueryBuilders.termsQuery("logType", logTypes));
            }

            searchSourceBuilder.query(boolQuery);
            searchSourceBuilder.size(maxQuerySize);
            searchSourceBuilder.fetchSource(LOG_INCLUDES, null);  // 只返回需要的字段
            searchRequest.source(searchSourceBuilder);

            // 执行查询
            SearchResponse searchResponse = esClient.search(searchRequest, RequestOptions.DEFAULT);

            // 提取hits并转换
            List<Map<String, Object>> hitMaps = extractHits(searchResponse);
            List<RawLog> logs = DataConverter.convertToLogList(hitMaps);

            log.debug("查询到日志数: {}", logs.size());
            return logs;

        } catch (IOException e) {
            log.error("查询原始日志失败: {}", e.getMessage(), e);
            return new ArrayList<>();
        }
    }

    /**
     * 从SearchResponse中提取hits数据
     * 
     * @param searchResponse ES查询响应
     * @return Map列表
     */
    private List<Map<String, Object>> extractHits(SearchResponse searchResponse) {
        if (searchResponse == null) {
            return new ArrayList<>();
        }

        List<Map<String, Object>> hitMaps = new ArrayList<>();

        // 获取hits
        SearchHit[] hits = searchResponse.getHits().getHits();

        // 遍历每个hit
        for (SearchHit hit : hits) {
            Map<String, Object> sourceMap = hit.getSourceAsMap();
            if (sourceMap != null) {
                hitMaps.add(sourceMap);
            }
        }

        return hitMaps;
    }

    /**
     * 获取查询统计信息
     */
    public void printQueryStats(SearchResponse searchResponse) {
        if (searchResponse != null) {
            log.info("查询统计:");
            log.info("  总命中数: {}", searchResponse.getHits().getTotalHits().value);
            log.info("  返回数: {}", searchResponse.getHits().getHits().length);
            log.info("  耗时: {}ms", searchResponse.getTook().getMillis());
        }
    }
}

