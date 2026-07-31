package top.oxff.model;

import lombok.Data;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 响应头改写配置数据模型
 * 仅保存可序列化的原始值，用于YAML持久化与导入导出
 */
@Data
public class ResponseHeaderConfig {
    /**
     * 格式模式：HTTP兼容（RFC1123）
     */
    public static final String FORMAT_MODE_RFC1123 = "RFC1123";

    /**
     * 格式模式：用户自定义pattern
     */
    public static final String FORMAT_MODE_CUSTOM = "CUSTOM";

    /**
     * 默认自定义日期格式
     */
    public static final String DEFAULT_DATE_PATTERN = "yyyy-MM-dd HH:mm:ss";

    /**
     * Expires字段缺失补充时的默认偏移分钟数
     */
    public static final int DEFAULT_EXPIRES_OFFSET_MINUTES = 60;

    /**
     * 响应头改写总开关
     */
    private boolean enabled;

    /**
     * 响应头改写生效的工具集合，独立于请求头管理的TOOL_FLAGS
     */
    private Set<Integer> responseToolFlags = new LinkedHashSet<>();

    /**
     * 是否启用Date字段改写
     */
    private boolean dateEnabled;

    /**
     * Date字段输出格式模式
     */
    private String dateFormatMode = FORMAT_MODE_RFC1123;

    /**
     * Date字段自定义格式
     */
    private String datePattern = DEFAULT_DATE_PATTERN;

    /**
     * Date字段目标时区ID，为空表示跟随插件运行环境的本地系统时区
     */
    private String dateZoneId;

    /**
     * 响应中不存在Date时是否补充该头
     */
    private boolean dateAddIfMissing;

    /**
     * 是否启用Expires字段改写
     */
    private boolean expiresEnabled;

    /**
     * Expires字段输出格式模式
     */
    private String expiresFormatMode = FORMAT_MODE_RFC1123;

    /**
     * Expires字段自定义格式
     */
    private String expiresPattern = DEFAULT_DATE_PATTERN;

    /**
     * Expires字段目标时区ID，为空表示跟随插件运行环境的本地系统时区
     */
    private String expiresZoneId;

    /**
     * 响应中不存在Expires时是否补充该头
     */
    private boolean expiresAddIfMissing;

    /**
     * 补充Expires时相对当前时间的偏移分钟数，允许为负表示已过期时刻
     */
    private int expiresOffsetMinutes = DEFAULT_EXPIRES_OFFSET_MINUTES;
}
