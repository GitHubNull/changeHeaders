package top.oxff.service;

import top.oxff.model.HttpDateHeaderSettings;
import top.oxff.model.ResponseHeaderConfig;

import java.time.ZonedDateTime;

/**
 * Expires响应头处理器
 * 解析服务器返回的原始Expires，保持时间点不变换算到目标时区后按配置格式输出；
 * 对 0、-1 等"立即过期"语义标记以及无法解析的取值一律原样保留，避免破坏缓存语义
 */
public class ExpiresHeaderHandler extends AbstractHttpDateHeaderHandler {

    public static final String HEADER_NAME = "Expires";

    private static final ExpiresHeaderHandler INSTANCE = new ExpiresHeaderHandler();

    private ExpiresHeaderHandler() {
    }

    public static ExpiresHeaderHandler getInstance() {
        return INSTANCE;
    }

    @Override
    public String getHeaderName() {
        return HEADER_NAME;
    }

    @Override
    protected HttpDateHeaderSettings buildSettings(ResponseHeaderConfig config) {
        return HttpDateHeaderSettings.of(config.isExpiresEnabled(), config.getExpiresFormatMode(),
                config.getExpiresPattern(), config.getExpiresZoneId(), config.isExpiresAddIfMissing(),
                config.getExpiresOffsetMinutes());
    }

    @Override
    protected String getParseErrorKey() {
        return "error.response.expires.parse";
    }

    @Override
    protected String getPatternErrorKey() {
        return "error.response.expires.pattern";
    }

    /**
     * 0、-1 等纯数字取值是HTTP约定的"已过期"标记，属正常语义，无需日志
     */
    @Override
    protected boolean shouldPreserve(String trimmedValue) {
        return trimmedValue.matches("[+-]?\\d+");
    }

    /**
     * 无法解析的过期时刻保持原样，不用当前时间覆盖
     */
    @Override
    protected ZonedDateTime onParseFailure(HttpDateHeaderSettings current) {
        return null;
    }
}
