package com.security.processchain.config;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Elasticsearch配置类
 * 配置RestHighLevelClient客户端
 */
@Configuration
public class ElasticsearchConfig {

    @Value("${elasticsearch.hosts}")
    private String hosts;

    @Value("${elasticsearch.username:}")
    private String username;

    @Value("${elasticsearch.password:}")
    private String password;

    @Value("${elasticsearch.connection-timeout:5000}")
    private int connectionTimeout;

    @Value("${elasticsearch.socket-timeout:60000}")
    private int socketTimeout;

    @Value("${elasticsearch.connection-request-timeout:5000}")
    private int connectionRequestTimeout;

    /**
     * 创建RestHighLevelClient Bean
     */
    @Bean
    public RestHighLevelClient restHighLevelClient() {
        // 解析hosts配置
        String[] hostArray = hosts.split(",");
        HttpHost[] httpHosts = new HttpHost[hostArray.length];
        
        for (int i = 0; i < hostArray.length; i++) {
            String host = hostArray[i].trim();
            String[] parts = host.split(":");
            String hostname = parts[0];
            int port = parts.length > 1 ? Integer.parseInt(parts[1]) : 9200;
            httpHosts[i] = new HttpHost(hostname, port, "http");
        }

        // 创建RestClientBuilder
        RestClientBuilder builder = RestClient.builder(httpHosts);

        // 设置超时时间
        builder.setRequestConfigCallback(requestConfigBuilder -> 
            requestConfigBuilder
                .setConnectTimeout(connectionTimeout)
                .setSocketTimeout(socketTimeout)
                .setConnectionRequestTimeout(connectionRequestTimeout)
        );

        // 如果配置了用户名密码，添加认证
        if (username != null && !username.isEmpty() && password != null && !password.isEmpty()) {
            final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            credentialsProvider.setCredentials(
                AuthScope.ANY,
                new UsernamePasswordCredentials(username, password)
            );

            builder.setHttpClientConfigCallback(httpClientBuilder -> 
                httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider)
            );
        }

        return new RestHighLevelClient(builder);
    }
}

