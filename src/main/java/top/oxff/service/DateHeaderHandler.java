package top.oxff.service;

import burp.BurpExtender;
import top.oxff.model.DateHeaderSettings;
import top.oxff.model.ResponseHeaderConfig;
import top.oxff.util.LanguageManager;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Date响应头处理器
 * 解析服务器返回的原始Date（通常为GMT英文格式），保持时间点不变换算到目标时区后按配置格式输出
 */
public class DateHeaderHandler implements ResponseHeaderHandler {

    public static final String HEADER_NAME = "Date";

    private static final DateHeaderHandler INSTANCE = new DateHeaderHandler();

    /**
     * 带时区信息的HTTP日期格式：RFC1123（IMF-fixdate）与RFC850
     */
    private static final DateTimeFormatter[] ZONED_PARSERS = new DateTimeFormatter[]{
            DateTimeFormatter.RFC_1123_DATE_TIME.withLocale(Locale.ENGLISH),
            DateTimeFormatter.ofPattern("EEEE, dd-MMM-yy HH:mm:ss zzz", Locale.ENGLISH)
    };

    /**
     * 不带时区信息的asctime格式，按GMT解释
     */
    private static final DateTimeFormatter ASCTIME_PARSER =
            DateTimeFormatter.ofPattern("EEE MMM d HH:mm:ss yyyy", Locale.ENGLISH);

    /**
     * 运行期快照，Swing线程写、HTTP线程读
     */
    private volatile DateHeaderSettings settings = DateHeaderSettings.defaults();

    /**
     * 解析/格式化失败仅记录首次日志，避免高频请求刷日志
     */
    private final AtomicBoolean parseErrorLogged = new AtomicBoolean(false);
    private final AtomicBoolean formatErrorLogged = new AtomicBoolean(false);

    private DateHeaderHandler() {
    }

    public static DateHeaderHandler getInstance() {
        return INSTANCE;
    }

    /**
     * 更新运行期快照
     *
     * @param newSettings 新快照，为null时忽略
     */
    public void updateSettings(DateHeaderSettings newSettings) {
        if (null == newSettings) {
            return;
        }
        this.settings = newSettings;
        parseErrorLogged.set(false);
        formatErrorLogged.set(false);
    }

    public DateHeaderSettings getSettings() {
        return settings;
    }

    @Override
    public String getHeaderName() {
        return HEADER_NAME;
    }

    @Override
    public boolean isEnabled() {
        return settings.isEnabled();
    }

    @Override
    public boolean isAddIfMissing() {
        return settings.isAddIfMissing();
    }

    @Override
    public void configure(ResponseHeaderConfig config) {
        // DateHeaderSettings.from 在校验失败时抛出异常，快照未替换，旧配置继续生效
        updateSettings(DateHeaderSettings.from(config));
    }

    @Override
    public String transform(String originalValue) {
        DateHeaderSettings current = settings;
        if (!current.isEnabled()) {
            return null;
        }

        ZonedDateTime target;
        if (null == originalValue || originalValue.trim().isEmpty()) {
            if (!current.isAddIfMissing()) {
                return null;
            }
            target = ZonedDateTime.now(current.getZone());
        } else {
            ZonedDateTime parsed = parseHttpDate(originalValue.trim());
            if (null == parsed) {
                if (parseErrorLogged.compareAndSet(false, true)) {
                    BurpExtender.logError(LanguageManager.getString("error.response.date.parse", originalValue.trim()));
                }
                target = ZonedDateTime.now(current.getZone());
            } else {
                target = parsed.withZoneSameInstant(current.getZone());
            }
        }

        try {
            return current.getOutputFormatter().format(target);
        } catch (Exception e) {
            if (formatErrorLogged.compareAndSet(false, true)) {
                BurpExtender.logError(LanguageManager.getString("error.response.date.pattern", e.getMessage()));
            }
            return null;
        }
    }

    /**
     * 按HTTP允许的三种日期格式依次尝试解析
     *
     * @param value 原始Date取值
     * @return 解析结果，全部失败返回null
     */
    private ZonedDateTime parseHttpDate(String value) {
        for (DateTimeFormatter parser : ZONED_PARSERS) {
            try {
                return ZonedDateTime.parse(value, parser);
            } catch (Exception ignored) {
                // 尝试下一种格式
            }
        }
        try {
            return LocalDateTime.parse(value, ASCTIME_PARSER).atZone(ZoneOffset.UTC);
        } catch (Exception ignored) {
            return null;
        }
    }
}
