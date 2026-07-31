package top.oxff.service;

import top.oxff.model.HttpDateHeaderSettings;
import top.oxff.model.ResponseHeaderConfig;

import java.time.ZonedDateTime;

/**
 * Last-Modified响应头处理器
 * 解析服务器返回的原始Last-Modified，保持时间点不变换算到目标时区后按配置格式输出；
 * 无法解析的取值一律原样保留，避免虚构资源修改时刻破坏条件请求与缓存协商
 */
public class LastModifiedHeaderHandler extends AbstractHttpDateHeaderHandler {

    public static final String HEADER_NAME = "Last-Modified";

    private static final LastModifiedHeaderHandler INSTANCE = new LastModifiedHeaderHandler();

    private LastModifiedHeaderHandler() {
    }

    public static LastModifiedHeaderHandler getInstance() {
        return INSTANCE;
    }

    @Override
    public String getHeaderName() {
        return HEADER_NAME;
    }

    @Override
    protected HttpDateHeaderSettings buildSettings(ResponseHeaderConfig config) {
        return HttpDateHeaderSettings.of(config.isLastModifiedEnabled(), config.getLastModifiedFormatMode(),
                config.getLastModifiedPattern(), config.getLastModifiedZoneId(), config.isLastModifiedAddIfMissing(),
                config.getLastModifiedOffsetMinutes());
    }

    @Override
    protected String getParseErrorKey() {
        return "error.response.lastModified.parse";
    }

    @Override
    protected String getPatternErrorKey() {
        return "error.response.lastModified.pattern";
    }

    /**
     * 无法解析的修改时刻保持原样，不用当前时间覆盖
     */
    @Override
    protected ZonedDateTime onParseFailure(HttpDateHeaderSettings current) {
        return null;
    }
}
