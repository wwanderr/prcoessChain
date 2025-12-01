package com.security.processchain.model;

import java.util.Map;

/**
 * 原始告警数据模型
 * 对应ES中的告警数据
 * 
 * 字段分类和说明：
 * 
 * 【基础字段】
 * - eventId: 事件ID（唯一标识）
 * - traceId: 追踪ID
 * - hostAddress: 主机地址
 * - hostName: 主机名
 * - deviceAddress: 设备地址
 * - processGuid: 进程GUID
 * - parentProcessGuid: 父进程GUID
 * - threatSeverity: 威胁等级（HIGH/MEDIUM/LOW）
 * - severity: 告警严重程度（数字）
 * - startTime: 开始时间
 * - endTime: 结束时间
 * - deviceAssetSubType: 设备资产子类型
 * - alarmName: 告警名称
 * - logType: 日志类型（process/file/network/domain/registry）
 * - opType: 操作类型（create/stop/connect等）
 * - eventType: 事件类型
 * - eventNum: 事件编号
 * 
 * 【攻击相关字段】（用于告警描述模板替换）
 * - attacker: 攻击者（IP或标识）
 * - victim: 受害者（IP或主机）
 * 
 * 【进程相关字段】
 * - processName: 进程名称
 * - processId: 进程ID
 * - image: 进程映像路径
 * - commandLine: 命令行
 * - processMd5: 进程MD5
 * - processUserName: 进程用户名
 * - sourceImage: 源进程映像
 * - destImage: 目标进程映像
 * - imageLoaded: 加载的映像文件
 * 
 * 【父进程相关字段】（用于创建虚拟父节点）
 * - parentProcessName: 父进程名称
 * - parentProcessId: 父进程ID
 * - parentImage: 父进程映像路径
 * - parentCommandLine: 父进程命令行
 * - parentProcessMd5: 父进程MD5
 * - parentProcessUserName: 父进程用户名
 * 
 * 【文件相关字段】
 * - fileName: 文件名
 * - fileMd5: 文件MD5
 * - targetFilename: 目标文件名
 * - fileHash: 文件哈希值
 * - fileContents: 文件内容
 * - creationUtcTime: 文件创建时间（UTC）
 * - previousCreationUtcTime: 文件原创建时间（UTC）
 * 
 * 【网络相关字段】
 * - srcAddress: 源地址
 * - srcPort: 源端口
 * - srcTransAddress: 源转发地址
 * - destAddress: 目标地址
 * - destPort: 目标端口
 * - destHostName: 目标主机名
 * 
 * 【域名相关字段】
 * - requestDomain: 请求域名
 * 
 * 【Web攻击相关字段】
 * - requestUrl: 请求URL
 * - responseCode: 响应码
 * - appProtocol: 应用协议
 * 
 * 【注册表相关字段】
 * - targetObject: 目标对象（注册表路径）
 * - regValue: 注册表值
 * - regNewName: 注册表新名称
 * 
 * 【签名相关字段】
 * - signature: 数字签名商
 * - company: 公司名
 * 
 * 【访问相关字段】
 * - grantedAccess: 访问掩码
 * - startAddress: 起始地址（注入起始地址等）
 * 
 * 【管道相关字段】
 * - pipeName: 管道名称
 * 
 * 【WMI相关字段】
 * - operation: 操作类型（WMI操作）
 * - wmiType: WMI类型
 * - wmiEventNamespace: WMI事件命名空间
 * - wmiName: WMI名称
 * - wmiQuery: WMI查询
 * - wmiDestination: WMI目标
 * - wmiConsumer: WMI消费者
 * - wmiFilter: WMI过滤器
 * 
 * 【其他字段】
 * - otherFields: 其他字段（Map形式存储未映射的字段）
 */
public class RawAlarm {
    private String eventId;
    private String traceId;
    private String hostAddress;
    private String hostName;
    private String processGuid;
    private String parentProcessGuid;
    private String threatSeverity;
    private Integer severity; // 告警严重程度（数字）
    private String startTime;
    private String endTime;
    private String collectorReceiptTime; // 采集器接收时间（用于实体排序）
    private String processStartTime; // 进程启动时间
    private String parentProcessStartTime; // 父进程启动时间
    private String deviceAssetSubType;
    private String alarmName;
    private String logType;
    private String opType;
    
    // 进程相关字段
    private String processName;
    private Integer processId;
    private String image;
    private String commandLine;
    private String processMd5;
    private String processUserName;
    
    // 父进程相关字段（用于创建虚拟父节点）
    private String parentProcessName;
    private Integer parentProcessId;
    private String parentImage;
    private String parentCommandLine;
    private String parentProcessMd5;
    private String parentProcessUserName;
    
    // 文件相关字段
    private String fileName;
    private String fileMd5;
    private String targetFilename;
    private String filePath;  // 文件路径
    private String fileType;  // 文件类型
    private String fileSize;  // 文件大小（字节）
    
    // 域名相关字段
    private String requestDomain;
    private String queryResults;  // DNS查询结果
    
    // 网络相关字段
    private String srcAddress;
    private String srcPort;
    private String destAddress;
    private String destPort;
    private String transProtocol;  // 传输协议（TCP/UDP）
    private String initiated;  // 是否主动发起连接
    
    // 注册表相关字段
    private String targetObject;
    private String regValue;
    private String regNewName;
    
    // Web攻击相关字段
    private String requestUrl;
    private String responseCode;
    private String appProtocol;
    
    // 攻击者和受害者
    private String attacker;
    private String victim;
    private String destHostName;
    
    // 事件相关字段
    private String eventType;
    private String deviceAddress;
    
    // 文件时间相关字段
    private String creationUtcTime;
    private String previousCreationUtcTime;
    
    // 签名相关字段
    private String signature;
    private String company;
    private String fileHash;
    
    // 进程相关字段（扩展）
    private String sourceImage;
    private String destImage;
    private String imageLoaded;
    
    // 访问相关字段
    private String grantedAccess;
    private String startAddress;
    
    // 文件相关字段（扩展）
    private String fileContents;
    
    // 管道相关字段
    private String pipeName;
    
    // WMI相关字段
    private String operation;
    private String wmiType;
    private String wmiEventNamespace;
    private String wmiName;
    private String wmiQuery;
    private String wmiDestination;
    private String wmiConsumer;
    private String wmiFilter;
    
    // 网络相关字段（扩展）
    private String srcTransAddress;
    
    // 事件编号
    private String eventNum;
    
    // 其他字段
    private Map<String, Object> otherFields;
    
    public RawAlarm() {}
    
    // Getters and Setters
    public String getEventId() {
        return eventId;
    }
    
    public void setEventId(String eventId) {
        this.eventId = eventId;
    }
    
    public String getTraceId() {
        return traceId;
    }
    
    public void setTraceId(String traceId) {
        this.traceId = traceId;
    }
    
    public String getHostAddress() {
        return hostAddress;
    }
    
    public void setHostAddress(String hostAddress) {
        this.hostAddress = hostAddress;
    }
    
    public String getProcessGuid() {
        return processGuid;
    }
    
    public void setProcessGuid(String processGuid) {
        this.processGuid = processGuid;
    }
    
    public String getParentProcessGuid() {
        return parentProcessGuid;
    }
    
    public void setParentProcessGuid(String parentProcessGuid) {
        this.parentProcessGuid = parentProcessGuid;
    }
    
    public String getThreatSeverity() {
        return threatSeverity;
    }
    
    public void setThreatSeverity(String threatSeverity) {
        this.threatSeverity = threatSeverity;
    }
    
    public String getStartTime() {
        return startTime;
    }
    
    public void setStartTime(String startTime) {
        this.startTime = startTime;
    }
    
    public String getEndTime() {
        return endTime;
    }
    
    public void setEndTime(String endTime) {
        this.endTime = endTime;
    }
    
    public String getCollectorReceiptTime() {
        return collectorReceiptTime;
    }
    
    public void setCollectorReceiptTime(String collectorReceiptTime) {
        this.collectorReceiptTime = collectorReceiptTime;
    }
    
    public String getProcessStartTime() {
        return processStartTime;
    }
    
    public void setProcessStartTime(String processStartTime) {
        this.processStartTime = processStartTime;
    }
    
    public String getParentProcessStartTime() {
        return parentProcessStartTime;
    }
    
    public void setParentProcessStartTime(String parentProcessStartTime) {
        this.parentProcessStartTime = parentProcessStartTime;
    }
    
    public String getDeviceAssetSubType() {
        return deviceAssetSubType;
    }
    
    public void setDeviceAssetSubType(String deviceAssetSubType) {
        this.deviceAssetSubType = deviceAssetSubType;
    }
    
    public String getAlarmName() {
        return alarmName;
    }
    
    public void setAlarmName(String alarmName) {
        this.alarmName = alarmName;
    }
    
    public String getLogType() {
        return logType;
    }
    
    public void setLogType(String logType) {
        this.logType = logType;
    }
    
    public String getOpType() {
        return opType;
    }
    
    public void setOpType(String opType) {
        this.opType = opType;
    }
    
    public Map<String, Object> getOtherFields() {
        return otherFields;
    }
    
    public void setOtherFields(Map<String, Object> otherFields) {
        this.otherFields = otherFields;
    }
    
    public String getHostName() {
        return hostName;
    }
    
    public void setHostName(String hostName) {
        this.hostName = hostName;
    }
    
    public Integer getSeverity() {
        return severity;
    }
    
    public void setSeverity(Integer severity) {
        this.severity = severity;
    }
    
    public String getProcessName() {
        return processName;
    }
    
    public void setProcessName(String processName) {
        this.processName = processName;
    }
    
    public Integer getProcessId() {
        return processId;
    }
    
    public void setProcessId(Integer processId) {
        this.processId = processId;
    }
    
    public String getImage() {
        return image;
    }
    
    public void setImage(String image) {
        this.image = image;
    }
    
    public String getCommandLine() {
        return commandLine;
    }
    
    public void setCommandLine(String commandLine) {
        this.commandLine = commandLine;
    }
    
    public String getProcessMd5() {
        return processMd5;
    }
    
    public void setProcessMd5(String processMd5) {
        this.processMd5 = processMd5;
    }
    
    public String getProcessUserName() {
        return processUserName;
    }
    
    public void setProcessUserName(String processUserName) {
        this.processUserName = processUserName;
    }
    
    public String getParentProcessName() {
        return parentProcessName;
    }
    
    public void setParentProcessName(String parentProcessName) {
        this.parentProcessName = parentProcessName;
    }
    
    public Integer getParentProcessId() {
        return parentProcessId;
    }
    
    public void setParentProcessId(Integer parentProcessId) {
        this.parentProcessId = parentProcessId;
    }
    
    public String getParentImage() {
        return parentImage;
    }
    
    public void setParentImage(String parentImage) {
        this.parentImage = parentImage;
    }
    
    public String getParentCommandLine() {
        return parentCommandLine;
    }
    
    public void setParentCommandLine(String parentCommandLine) {
        this.parentCommandLine = parentCommandLine;
    }
    
    public String getParentProcessMd5() {
        return parentProcessMd5;
    }
    
    public void setParentProcessMd5(String parentProcessMd5) {
        this.parentProcessMd5 = parentProcessMd5;
    }
    
    public String getParentProcessUserName() {
        return parentProcessUserName;
    }
    
    public void setParentProcessUserName(String parentProcessUserName) {
        this.parentProcessUserName = parentProcessUserName;
    }
    
    public String getFileName() {
        return fileName;
    }
    
    public void setFileName(String fileName) {
        this.fileName = fileName;
    }
    
    public String getFileMd5() {
        return fileMd5;
    }
    
    public void setFileMd5(String fileMd5) {
        this.fileMd5 = fileMd5;
    }
    
    public String getTargetFilename() {
        return targetFilename;
    }
    
    public void setTargetFilename(String targetFilename) {
        this.targetFilename = targetFilename;
    }
    
    public String getFilePath() {
        return filePath;
    }
    
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }
    
    public String getFileType() {
        return fileType;
    }
    
    public void setFileType(String fileType) {
        this.fileType = fileType;
    }
    
    public String getFileSize() {
        return fileSize;
    }
    
    public void setFileSize(String fileSize) {
        this.fileSize = fileSize;
    }
    
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
    
    public String getSrcAddress() {
        return srcAddress;
    }
    
    public void setSrcAddress(String srcAddress) {
        this.srcAddress = srcAddress;
    }
    
    public String getSrcPort() {
        return srcPort;
    }
    
    public void setSrcPort(String srcPort) {
        this.srcPort = srcPort;
    }
    
    public String getDestAddress() {
        return destAddress;
    }
    
    public void setDestAddress(String destAddress) {
        this.destAddress = destAddress;
    }
    
    public String getDestPort() {
        return destPort;
    }
    
    public void setDestPort(String destPort) {
        this.destPort = destPort;
    }
    
    public String getTransProtocol() {
        return transProtocol;
    }
    
    public void setTransProtocol(String transProtocol) {
        this.transProtocol = transProtocol;
    }
    
    public String getInitiated() {
        return initiated;
    }
    
    public void setInitiated(String initiated) {
        this.initiated = initiated;
    }
    
    public String getTargetObject() {
        return targetObject;
    }
    
    public void setTargetObject(String targetObject) {
        this.targetObject = targetObject;
    }
    
    public String getRegValue() {
        return regValue;
    }
    
    public void setRegValue(String regValue) {
        this.regValue = regValue;
    }
    
    public String getRegNewName() {
        return regNewName;
    }
    
    public void setRegNewName(String regNewName) {
        this.regNewName = regNewName;
    }
    
    public String getRequestUrl() {
        return requestUrl;
    }
    
    public void setRequestUrl(String requestUrl) {
        this.requestUrl = requestUrl;
    }
    
    public String getResponseCode() {
        return responseCode;
    }
    
    public void setResponseCode(String responseCode) {
        this.responseCode = responseCode;
    }
    
    public String getAppProtocol() {
        return appProtocol;
    }
    
    public void setAppProtocol(String appProtocol) {
        this.appProtocol = appProtocol;
    }
    
    public String getAttacker() {
        return attacker;
    }
    
    public void setAttacker(String attacker) {
        this.attacker = attacker;
    }
    
    public String getVictim() {
        return victim;
    }
    
    public void setVictim(String victim) {
        this.victim = victim;
    }
    
    public String getDestHostName() {
        return destHostName;
    }
    
    public void setDestHostName(String destHostName) {
        this.destHostName = destHostName;
    }
    
    public String getEventType() {
        return eventType;
    }
    
    public void setEventType(String eventType) {
        this.eventType = eventType;
    }
    
    public String getDeviceAddress() {
        return deviceAddress;
    }
    
    public void setDeviceAddress(String deviceAddress) {
        this.deviceAddress = deviceAddress;
    }
    
    public String getCreationUtcTime() {
        return creationUtcTime;
    }
    
    public void setCreationUtcTime(String creationUtcTime) {
        this.creationUtcTime = creationUtcTime;
    }
    
    public String getPreviousCreationUtcTime() {
        return previousCreationUtcTime;
    }
    
    public void setPreviousCreationUtcTime(String previousCreationUtcTime) {
        this.previousCreationUtcTime = previousCreationUtcTime;
    }
    
    public String getSignature() {
        return signature;
    }
    
    public void setSignature(String signature) {
        this.signature = signature;
    }
    
    public String getCompany() {
        return company;
    }
    
    public void setCompany(String company) {
        this.company = company;
    }
    
    public String getFileHash() {
        return fileHash;
    }
    
    public void setFileHash(String fileHash) {
        this.fileHash = fileHash;
    }
    
    public String getSourceImage() {
        return sourceImage;
    }
    
    public void setSourceImage(String sourceImage) {
        this.sourceImage = sourceImage;
    }
    
    public String getDestImage() {
        return destImage;
    }
    
    public void setDestImage(String destImage) {
        this.destImage = destImage;
    }
    
    public String getImageLoaded() {
        return imageLoaded;
    }
    
    public void setImageLoaded(String imageLoaded) {
        this.imageLoaded = imageLoaded;
    }
    
    public String getGrantedAccess() {
        return grantedAccess;
    }
    
    public void setGrantedAccess(String grantedAccess) {
        this.grantedAccess = grantedAccess;
    }
    
    public String getStartAddress() {
        return startAddress;
    }
    
    public void setStartAddress(String startAddress) {
        this.startAddress = startAddress;
    }
    
    public String getFileContents() {
        return fileContents;
    }
    
    public void setFileContents(String fileContents) {
        this.fileContents = fileContents;
    }
    
    public String getPipeName() {
        return pipeName;
    }
    
    public void setPipeName(String pipeName) {
        this.pipeName = pipeName;
    }
    
    public String getOperation() {
        return operation;
    }
    
    public void setOperation(String operation) {
        this.operation = operation;
    }
    
    public String getWmiType() {
        return wmiType;
    }
    
    public void setWmiType(String wmiType) {
        this.wmiType = wmiType;
    }
    
    public String getWmiEventNamespace() {
        return wmiEventNamespace;
    }
    
    public void setWmiEventNamespace(String wmiEventNamespace) {
        this.wmiEventNamespace = wmiEventNamespace;
    }
    
    public String getWmiName() {
        return wmiName;
    }
    
    public void setWmiName(String wmiName) {
        this.wmiName = wmiName;
    }
    
    public String getWmiQuery() {
        return wmiQuery;
    }
    
    public void setWmiQuery(String wmiQuery) {
        this.wmiQuery = wmiQuery;
    }
    
    public String getWmiDestination() {
        return wmiDestination;
    }
    
    public void setWmiDestination(String wmiDestination) {
        this.wmiDestination = wmiDestination;
    }
    
    public String getWmiConsumer() {
        return wmiConsumer;
    }
    
    public void setWmiConsumer(String wmiConsumer) {
        this.wmiConsumer = wmiConsumer;
    }
    
    public String getWmiFilter() {
        return wmiFilter;
    }
    
    public void setWmiFilter(String wmiFilter) {
        this.wmiFilter = wmiFilter;
    }
    
    public String getSrcTransAddress() {
        return srcTransAddress;
    }
    
    public void setSrcTransAddress(String srcTransAddress) {
        this.srcTransAddress = srcTransAddress;
    }
    
    public String getEventNum() {
        return eventNum;
    }
    
    public void setEventNum(String eventNum) {
        this.eventNum = eventNum;
    }
    
    @Override
    public String toString() {
        return "RawAlarm{" +
                "eventId='" + eventId + '\'' +
                ", traceId='" + traceId + '\'' +
                ", hostAddress='" + hostAddress + '\'' +
                ", processGuid='" + processGuid + '\'' +
                ", threatSeverity='" + threatSeverity + '\'' +
                '}';
    }
}



