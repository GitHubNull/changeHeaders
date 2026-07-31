package top.oxff.service;

import burp.BurpExtender;
import top.oxff.model.ResponseHeaderConfig;
import top.oxff.util.LanguageManager;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 响应头改写服务
 * 维护总开关、生效工具集合与处理器注册表，是HTTP线程与UI线程之间的唯一入口
 * 新增响应头字段处理：实现 {@link ResponseHeaderHandler} 后在此注册即可
 */
public class ResponseHeaderService {

    private static final List<ResponseHeaderHandler> HANDLERS = new CopyOnWriteArrayList<>();

    private static final Set<Integer> RESPONSE_TOOL_FLAGS = ConcurrentHashMap.newKeySet();

    private static volatile boolean enabled = false;

    /**
     * 当前生效的配置，作为持久化与UI回填的数据源
     */
    private static volatile ResponseHeaderConfig currentConfig = new ResponseHeaderConfig();

    static {
        HANDLERS.add(DateHeaderHandler.getInstance());
    }

    private ResponseHeaderService() {
    }

    /**
     * 注册响应头处理器
     *
     * @param handler 处理器
     */
    public static void register(ResponseHeaderHandler handler) {
        if (null != handler) {
            HANDLERS.add(handler);
        }
    }

    public static List<ResponseHeaderHandler> getHandlers() {
        return Collections.unmodifiableList(HANDLERS);
    }

    public static boolean isEnabled() {
        return enabled;
    }

    /**
     * 快速判断当前工具的响应是否需要处理
     * 供HTTP监听器在解析响应报文之前短路，避免无谓的性能开销
     *
     * @param toolFlag Burp工具标志
     * @return true表示需要处理
     */
    public static boolean isActive(int toolFlag) {
        if (!enabled || !RESPONSE_TOOL_FLAGS.contains(toolFlag)) {
            return false;
        }
        for (ResponseHeaderHandler handler : HANDLERS) {
            if (handler.isEnabled()) {
                return true;
            }
        }
        return false;
    }

    /**
     * 应用配置：校验失败时抛出异常且不改变已生效的状态
     *
     * @param config 响应头配置
     * @throws IllegalArgumentException 配置非法（如自定义日期格式无效）
     */
    public static void applyConfig(ResponseHeaderConfig config) {
        if (null == config) {
            return;
        }

        // 先让各处理器完成校验与配置装载，任一处理器抛出异常则整体不生效
        for (ResponseHeaderHandler handler : HANDLERS) {
            handler.configure(config);
        }

        enabled = config.isEnabled();
        RESPONSE_TOOL_FLAGS.clear();
        if (null != config.getResponseToolFlags()) {
            RESPONSE_TOOL_FLAGS.addAll(config.getResponseToolFlags());
        }
        currentConfig = copyOf(config);
    }

    /**
     * 加载持久化配置：容错处理，非法的自定义格式回退为HTTP兼容模式
     *
     * @param config 响应头配置
     */
    public static void loadConfig(ResponseHeaderConfig config) {
        if (null == config) {
            return;
        }
        try {
            applyConfig(config);
        } catch (Exception e) {
            BurpExtender.logError(LanguageManager.getString("error.response.date.pattern", e.getMessage()));
            ResponseHeaderConfig fallback = copyOf(config);
            fallback.setDateFormatMode(ResponseHeaderConfig.FORMAT_MODE_RFC1123);
            try {
                applyConfig(fallback);
            } catch (Exception ignored) {
                applyConfig(new ResponseHeaderConfig());
            }
        }
    }

    /**
     * 获取当前配置的副本，用于持久化与导出
     *
     * @return 配置副本
     */
    public static ResponseHeaderConfig buildConfig() {
        ResponseHeaderConfig config = copyOf(currentConfig);
        config.setEnabled(enabled);
        config.setResponseToolFlags(new LinkedHashSet<>(RESPONSE_TOOL_FLAGS));
        return config;
    }

    /**
     * 恢复响应头改写的默认配置，不影响请求头管理与偏好配置
     *
     * @return 默认配置
     */
    public static ResponseHeaderConfig resetDefaults() {
        ResponseHeaderConfig defaults = new ResponseHeaderConfig();
        applyConfig(defaults);
        return defaults;
    }

    private static ResponseHeaderConfig copyOf(ResponseHeaderConfig source) {
        ResponseHeaderConfig target = new ResponseHeaderConfig();
        target.setEnabled(source.isEnabled());
        target.setResponseToolFlags(null == source.getResponseToolFlags()
                ? new LinkedHashSet<>() : new LinkedHashSet<>(source.getResponseToolFlags()));
        target.setDateEnabled(source.isDateEnabled());
        target.setDateFormatMode(source.getDateFormatMode());
        target.setDatePattern(source.getDatePattern());
        target.setDateZoneId(source.getDateZoneId());
        target.setDateAddIfMissing(source.isDateAddIfMissing());
        return target;
    }
}
