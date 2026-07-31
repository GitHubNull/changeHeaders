package top.oxff.service;

import top.oxff.model.HttpDateHeaderSettings;
import top.oxff.model.ResponseHeaderConfig;

/**
 * Date响应头处理器
 * 解析服务器返回的原始Date（通常为GMT英文格式），保持时间点不变换算到目标时区后按配置格式输出
 */
public class DateHeaderHandler extends AbstractHttpDateHeaderHandler {

    public static final String HEADER_NAME = "Date";

    private static final DateHeaderHandler INSTANCE = new DateHeaderHandler();

    private DateHeaderHandler() {
    }

    public static DateHeaderHandler getInstance() {
        return INSTANCE;
    }

    @Override
    public String getHeaderName() {
        return HEADER_NAME;
    }

    @Override
    protected HttpDateHeaderSettings buildSettings(ResponseHeaderConfig config) {
        // Date表示报文生成时刻，补充场景直接取当前时间，故偏移恒为0
        return HttpDateHeaderSettings.of(config.isDateEnabled(), config.getDateFormatMode(),
                config.getDatePattern(), config.getDateZoneId(), config.isDateAddIfMissing(), 0);
    }

    @Override
    protected String getParseErrorKey() {
        return "error.response.date.parse";
    }

    @Override
    protected String getPatternErrorKey() {
        return "error.response.date.pattern";
    }
}
