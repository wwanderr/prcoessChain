package com.security.processchain.service;

/**
 * 域名实体
 */
public class DomainEntity {
    private String requestDomain;
    private String queryResults;
    
    public DomainEntity() {}
    
    public String getRequestDomain() {
        return requestDomain;
    }
    
    public void setRequestDomain(String requestDomain) {
        this.requestDomain = requestDomain;
    }
    
    public String getQueryResults() {
        return queryResults;
    }
    
    public void setQueryResults(String queryResults) {
        this.queryResults = queryResults;
    }
}



