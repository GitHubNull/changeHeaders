package top.oxff.service;

import java.util.*;

/**
 * 偏好匹配逻辑工具类
 * 根据持久化键名和内置关键词确定自动勾选的请求头
 *
 * 优先级：持久化key（精确匹配）> 内置关键词（包含匹配）> 不勾选
 * 持久化key和内置关键词不会重复匹配同一个请求头
 */
public class PreferenceMatcher {

    /**
     * 根据偏好规则确定哪些候选请求头应被自动勾选
     *
     * @param candidateKeys   候选请求头键名列表
     * @param persistedKeys   持久化的请求头键名列表
     * @param builtinKeywords 内置匹配关键词列表
     * @return 应被自动勾选的请求头键名集合
     */
    public static Set<String> determineAutoSelectedKeys(
            List<String> candidateKeys,
            List<String> persistedKeys,
            List<String> builtinKeywords) {

        Set<String> result = new HashSet<>();
        if (candidateKeys == null || candidateKeys.isEmpty()) {
            return result;
        }

        // 构建持久化key的小写集合用于精确匹配
        Set<String> persistedLower = new HashSet<>();
        if (persistedKeys != null) {
            for (String key : persistedKeys) {
                if (key != null && !key.trim().isEmpty()) {
                    persistedLower.add(key.trim().toLowerCase());
                }
            }
        }

        // 构建关键词的小写集合
        Set<String> keywordsLower = new HashSet<>();
        if (builtinKeywords != null) {
            for (String keyword : builtinKeywords) {
                if (keyword != null && !keyword.trim().isEmpty()) {
                    keywordsLower.add(keyword.trim().toLowerCase());
                }
            }
        }

        // 第一步：精确匹配持久化key
        Set<String> matchedByPersistence = new HashSet<>();
        for (String candidate : candidateKeys) {
            if (candidate == null || candidate.trim().isEmpty()) continue;
            String candidateLower = candidate.trim().toLowerCase();
            if (persistedLower.contains(candidateLower)) {
                result.add(candidate);
                matchedByPersistence.add(candidateLower);
            }
        }

        // 第二步：对未被持久化匹配的候选key，检查是否包含内置关键词
        for (String candidate : candidateKeys) {
            if (candidate == null || candidate.trim().isEmpty()) continue;
            String candidateLower = candidate.trim().toLowerCase();

            // 跳过已被持久化匹配的
            if (matchedByPersistence.contains(candidateLower)) continue;

            // 检查是否包含任一关键词
            for (String keyword : keywordsLower) {
                if (candidateLower.contains(keyword)) {
                    result.add(candidate);
                    break;
                }
            }
        }

        return result;
    }
}
