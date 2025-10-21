package com.security.processchain.util;

import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/**
 * 时间工具类
 * 使用 Java 8+ 的 DateTimeFormatter（线程安全）
 */
@Slf4j
public class TimeUtil {
    
    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    /**
     * 计算时间前10分钟
     * 
     * @param timeStr 时间字符串
     * @return 前10分钟的时间字符串,如果解析失败返回原字符串
     */
    public static String getTimeBefore10Minutes(String timeStr) {
        if (timeStr == null || timeStr.trim().isEmpty()) {
            log.warn("时间字符串为空，无法计算前10分钟");
            return timeStr;
        }
        
        try {
            LocalDateTime dateTime = LocalDateTime.parse(timeStr, DATE_TIME_FORMATTER);
            LocalDateTime result = dateTime.minusMinutes(10);
            return result.format(DATE_TIME_FORMATTER);
        } catch (DateTimeParseException e) {
            log.warn("时间字符串解析失败: {}, 错误: {}", timeStr, e.getMessage());
            return timeStr;
        } catch (Exception e) {
            log.warn("计算时间前10分钟失败: {}", e.getMessage());
            return timeStr;
        }
    }
    
    /**
     * 计算时间后10分钟
     * 
     * @param timeStr 时间字符串
     * @return 后10分钟的时间字符串,如果解析失败返回原字符串
     */
    public static String getTimeAfter10Minutes(String timeStr) {
        if (timeStr == null || timeStr.trim().isEmpty()) {
            log.warn("时间字符串为空，无法计算后10分钟");
            return timeStr;
        }
        
        try {
            LocalDateTime dateTime = LocalDateTime.parse(timeStr, DATE_TIME_FORMATTER);
            LocalDateTime result = dateTime.plusMinutes(10);
            return result.format(DATE_TIME_FORMATTER);
        } catch (DateTimeParseException e) {
            log.warn("时间字符串解析失败: {}, 错误: {}", timeStr, e.getMessage());
            return timeStr;
        } catch (Exception e) {
            log.warn("计算时间后10分钟失败: {}", e.getMessage());
            return timeStr;
        }
    }
    
    /**
     * 检查是否是同一天
     * 
     * @param time1 时间1
     * @param time2 时间2
     * @return 是否同一天,如果解析失败返回false
     */
    public static boolean isSameDay(String time1, String time2) {
        if (time1 == null || time1.trim().isEmpty() || 
            time2 == null || time2.trim().isEmpty()) {
            log.warn("时间字符串为空，无法比较日期");
            return false;
        }
        
        try {
            LocalDateTime dateTime1 = LocalDateTime.parse(time1, DATE_TIME_FORMATTER);
            LocalDateTime dateTime2 = LocalDateTime.parse(time2, DATE_TIME_FORMATTER);
            
            return dateTime1.toLocalDate().equals(dateTime2.toLocalDate());
        } catch (DateTimeParseException e) {
            log.warn("时间字符串解析失败: time1={}, time2={}, 错误: {}", time1, time2, e.getMessage());
            return false;
        } catch (Exception e) {
            log.warn("比较日期失败: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * 验证时间字符串格式是否正确
     * 
     * @param timeStr 时间字符串
     * @return 是否格式正确
     */
    public static boolean isValidTimeFormat(String timeStr) {
        if (timeStr == null || timeStr.trim().isEmpty()) {
            return false;
        }
        
        try {
            LocalDateTime.parse(timeStr, DATE_TIME_FORMATTER);
            return true;
        } catch (DateTimeParseException e) {
            return false;
        }
    }
    
    /**
     * 安全格式化当前时间
     * 
     * @return 格式化的当前时间字符串
     */
    public static String getCurrentTimeString() {
        try {
            return LocalDateTime.now().format(DATE_TIME_FORMATTER);
        } catch (Exception e) {
            log.error("格式化当前时间失败: {}", e.getMessage());
            return "";
        }
    }
    
    /**
     * 在指定时间上增加小时数
     * 
     * @param timeStr 时间字符串
     * @param hours 要增加的小时数
     * @return 计算后的时间字符串，如果解析失败返回原字符串
     */
    public static String addHours(String timeStr, int hours) {
        if (timeStr == null || timeStr.trim().isEmpty()) {
            log.warn("时间字符串为空，无法增加小时");
            return timeStr;
        }
        
        try {
            LocalDateTime dateTime = LocalDateTime.parse(timeStr, DATE_TIME_FORMATTER);
            LocalDateTime result = dateTime.plusHours(hours);
            return result.format(DATE_TIME_FORMATTER);
        } catch (DateTimeParseException e) {
            log.warn("时间字符串解析失败: {}, 错误: {}", timeStr, e.getMessage());
            return timeStr;
        } catch (Exception e) {
            log.warn("增加小时失败: {}", e.getMessage());
            return timeStr;
        }
    }
}

