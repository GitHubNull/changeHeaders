package top.oxff.util;

import lombok.Getter;

import java.util.Locale;
import java.util.ResourceBundle;

/**
 * 语言资源包管理器
 * 支持国际化功能，默认语言为中文
 */
public class LanguageManager {
    private static final String BUNDLE_NAME = "messages";
    /**
     * -- GETTER --
     *  获取当前语言环境
     *
     */
    @Getter
    private static Locale currentLocale = Locale.CHINESE;
    private static ResourceBundle messageBundle = ResourceBundle.getBundle(BUNDLE_NAME, currentLocale);

    /**
     * 设置语言环境
     * @param locale 语言环境
     */
    public static void setLocale(Locale locale) {
        currentLocale = locale;
        messageBundle = ResourceBundle.getBundle(BUNDLE_NAME, currentLocale);
    }

    /**
     * 获取指定键的本地化字符串
     * @param key 资源键
     * @return 本地化字符串
     */
    public static String getString(String key) {
        try {
            return messageBundle.getString(key);
        } catch (Exception e) {
            // 如果找不到键，则返回键本身
            return key;
        }
    }

    /**
     * 获取指定键的本地化字符串，支持格式化参数
     * @param key 资源键
     * @param params 格式化参数
     * @return 本地化字符串
     */
    public static String getString(String key, Object... params) {
        try {
            String pattern = messageBundle.getString(key);
            return String.format(pattern, params);
        } catch (Exception e) {
            // 如果找不到键，则返回键本身
            return key;
        }
    }
}