package top.oxff.model;

import lombok.Data;

import java.util.List;

/**
 * 偏好配置数据模型
 * 用于偏好数据的YAML导入导出
 */
@Data
public class PreferenceConfig {
    private List<String> persistedHeaderKeys;
    private List<String> builtinKeywords;
    private long exportedAt;
}
