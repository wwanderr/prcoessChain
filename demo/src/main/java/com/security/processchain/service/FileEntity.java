package com.security.processchain.service;

/**
 * 文件实体
 */
public class FileEntity {
    private String filePath;
    private String targetFilename;
    private Long fileSize;
    private String fileMd5;
    private String fileType;
    private String fileName;
    
    public FileEntity() {}
    
    public String getFilePath() {
        return filePath;
    }
    
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }
    
    public String getTargetFilename() {
        return targetFilename;
    }
    
    public void setTargetFilename(String targetFilename) {
        this.targetFilename = targetFilename;
    }
    
    public Long getFileSize() {
        return fileSize;
    }
    
    public void setFileSize(Long fileSize) {
        this.fileSize = fileSize;
    }
    
    public String getFileMd5() {
        return fileMd5;
    }
    
    public void setFileMd5(String fileMd5) {
        this.fileMd5 = fileMd5;
    }
    
    public String getFileType() {
        return fileType;
    }
    
    public void setFileType(String fileType) {
        this.fileType = fileType;
    }
    
    public String getFileName() {
        return fileName;
    }
    
    public void setFileName(String fileName) {
        this.fileName = fileName;
    }
}



