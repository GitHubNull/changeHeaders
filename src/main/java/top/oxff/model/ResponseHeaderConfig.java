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
}
