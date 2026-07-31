package top.oxff.model;

import top.oxff.util.LanguageManager;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * HTTP日期类响应头改写的运行期不可变快照
 * 由Swing线程构建、HTTP线程只读，配合volatile引用实现无锁的线程安全
 */
public final class HttpDateHeaderSettings {

    private final boolean enabled;
    private final ZoneId zone;
    private final DateTimeFormatter outputFormatter;
    private final boolean addIfMissing;

    /**
     * 缺失补充场景下相对当前时间的偏移分钟数，Date字段恒为0
     */
    private final int offsetMinutes;

    public HttpDateHeaderSettings(boolean enabled, ZoneId zone, DateTimeFormatter outputFormatter,
                                  boolean addIfMissing, int offsetMinutes) {
        this.enabled = enabled;
        this.zone = zone;
        this.outputFormatter = outputFormatter;
        this.addIfMissing = addIfMissing;
        this.offsetMinutes = offsetMinutes;
    }

    /**
     * 根据配置项构建运行期快照
     *
     * @param enabled       是否启用改写
     * @param formatMode    输出格式模式
     * @param pattern       自定义格式
     * @param zoneId        目标时区ID，为空表示本地系统时区
     * @param addIfMissing  响应缺失该头时是否补充
     * @param offsetMinutes 补充场景下相对当前时间的偏移分钟数
     * @return 不可变快照
     * @throws IllegalArgumentException 自定义格式非法时抛出
     */
    public static HttpDateHeaderSettings of(boolean enabled, String formatMode, String pattern,
                                            String zoneId, boolean addIfMissing, int offsetMinutes) {
        ZoneId zone = resolveZone(zoneId);
        DateTimeFormatter formatter = buildFormatter(formatMode, pattern);

        // 提前试跑一次，暴露编译期通过但格式化时才失败的pattern
        formatter.format(ZonedDateTime.now(zone));

        return new HttpDateHeaderSettings(enabled, zone, formatter, addIfMissing, offsetMinutes);
    }

    /**
     * 解析时区ID，为空或非法时回退到本地系统时区
     *
     * @param zoneId 时区ID
     * @return 时区对象
     */
    public static ZoneId resolveZone(String zoneId) {
        if (null == zoneId || zoneId.trim().isEmpty()) {
            return ZoneId.systemDefault();
        }
        try {
            return ZoneId.of(zoneId.trim());
        } catch (Exception e) {
            return ZoneId.systemDefault();
        }
    }

    /**
     * 构建输出格式化器
     * HTTP兼容模式固定使用英文RFC1123格式，自定义模式使用当前语言环境
     *
     * @param formatMode 输出格式模式
     * @param pattern    自定义格式
     * @return 格式化器
     * @throws IllegalArgumentException 自定义格式非法时抛出
     */
    public static DateTimeFormatter buildFormatter(String formatMode, String pattern) {
        if (ResponseHeaderConfig.FORMAT_MODE_CUSTOM.equals(formatMode)) {
            if (null == pattern || pattern.trim().isEmpty()) {
                throw new IllegalArgumentException("date pattern is empty");
            }
            Locale locale = LanguageManager.getCurrentLocale();
            return DateTimeFormatter.ofPattern(pattern, null == locale ? Locale.getDefault() : locale);
        }
        return DateTimeFormatter.RFC_1123_DATE_TIME.withLocale(Locale.ENGLISH);
    }

    /**
     * 默认快照：关闭状态、本地时区、RFC1123格式、零偏移
     *
     * @return 默认快照
     */
    public static HttpDateHeaderSettings defaults() {
        return new HttpDateHeaderSettings(false, ZoneId.systemDefault(),
                DateTimeFormatter.RFC_1123_DATE_TIME.withLocale(Locale.ENGLISH), false, 0);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public ZoneId getZone() {
        return zone;
    }

    public DateTimeFormatter getOutputFormatter() {
        return outputFormatter;
    }

    public boolean isAddIfMissing() {
        return addIfMissing;
    }

    public int getOffsetMinutes() {
        return offsetMinutes;
    }
}
