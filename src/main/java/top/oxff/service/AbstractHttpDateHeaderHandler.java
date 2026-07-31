package top.oxff.service;

import burp.BurpExtender;
import top.oxff.model.HttpDateHeaderSettings;
import top.oxff.model.ResponseHeaderConfig;
import top.oxff.util.LanguageManager;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * HTTP日期类响应头处理器基类
 * 承载解析（RFC1123/RFC850/asctime）、时区换算、格式化与单次错误日志等共性逻辑，
 * 子类只需声明配置来源与差异化的取值策略
 */
public abstract class AbstractHttpDateHeaderHandler implements ResponseHeaderHandler {

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
    private volatile HttpDateHeaderSettings settings = HttpDateHeaderSettings.defaults();

    /**
     * 解析/格式化失败仅记录首次日志，避免高频请求刷日志
     */
    private final AtomicBoolean parseErrorLogged = new AtomicBoolean(false);
    private final AtomicBoolean formatErrorLogged = new AtomicBoolean(false);

    /**
     * 更新运行期快照
     *
     * @param newSettings 新快照，为null时忽略
     */
    public void updateSettings(HttpDateHeaderSettings newSettings) {
        if (null == newSettings) {
            return;
        }
        this.settings = newSettings;
        parseErrorLogged.set(false);
        formatErrorLogged.set(false);
    }

    public HttpDateHeaderSettings getSettings() {
        return settings;
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
    public final void configure(ResponseHeaderConfig config) {
        // buildSettings 在校验失败时抛出异常，快照未替换，旧配置继续生效
        updateSettings(buildSettings(config));
    }

    @Override
    public final String transform(String originalValue) {
        HttpDateHeaderSettings current = settings;
        if (!current.isEnabled()) {
            return null;
        }

        ZonedDateTime target;
        if (null == originalValue || originalValue.trim().isEmpty()) {
            if (!current.isAddIfMissing()) {
                return null;
            }
            target = ZonedDateTime.now(current.getZone()).plusMinutes(current.getOffsetMinutes());
        } else {
            String trimmed = originalValue.trim();
            if (shouldPreserve(trimmed)) {
                return null;
            }

            ZonedDateTime parsed = parseHttpDate(trimmed);
            if (null == parsed) {
                if (parseErrorLogged.compareAndSet(false, true)) {
                    BurpExtender.logError(LanguageManager.getString(getParseErrorKey(), trimmed));
                }
                target = onParseFailure(current);
                if (null == target) {
                    return null;
                }
            } else {
                target = parsed.withZoneSameInstant(current.getZone());
            }
        }

        try {
            return current.getOutputFormatter().format(target);
        } catch (Exception e) {
            if (formatErrorLogged.compareAndSet(false, true)) {
                BurpExtender.logError(LanguageManager.getString(getPatternErrorKey(), e.getMessage()));
            }
            return null;
        }
    }

    /**
     * 从配置中读取本字段的配置项并构建运行期快照
     *
     * @param config 响应头配置
     * @return 不可变快照
     * @throws IllegalArgumentException 配置非法
     */
    protected abstract HttpDateHeaderSettings buildSettings(ResponseHeaderConfig config);

    /**
     * 原始取值解析失败时的日志文案键
     *
     * @return 资源键
     */
    protected abstract String getParseErrorKey();

    /**
     * 输出格式非法时的日志文案键
     *
     * @return 资源键
     */
    protected abstract String getPatternErrorKey();

    /**
     * 原始取值是否保持不改写
     *
     * @param trimmedValue 去空白后的原始取值
     * @return true表示原样保留
     */
    protected boolean shouldPreserve(String trimmedValue) {
        return false;
    }

    /**
     * 原始取值解析失败时使用的目标时间
     *
     * @param current 运行期快照
     * @return 目标时间；返回null表示不改写
     */
    protected ZonedDateTime onParseFailure(HttpDateHeaderSettings current) {
        return ZonedDateTime.now(current.getZone());
    }

    /**
     * 按HTTP允许的三种日期格式依次尝试解析
     *
     * @param value 原始取值
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
