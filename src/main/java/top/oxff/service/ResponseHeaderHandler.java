package top.oxff.service;

import top.oxff.model.ResponseHeaderConfig;

/**
 * 响应头处理器接口
 * 每个实现负责一个响应头字段的改写逻辑，新增字段只需实现该接口并注册到
 * {@link ResponseHeaderService}
 */
public interface ResponseHeaderHandler {

    /**
     * 处理的响应头名称，如 Date
     *
     * @return 响应头名称
     */
    String getHeaderName();

    /**
     * 当前是否启用改写
     *
     * @return true表示启用
     */
    boolean isEnabled();

    /**
     * 响应中不存在该头时是否补充
     *
     * @return true表示补充
     */
    boolean isAddIfMissing();

    /**
     * 装载配置
     * 实现方需先完成校验再更新自身运行期状态，保证抛出异常时不产生半生效状态
     *
     * @param config 响应头配置
     * @throws IllegalArgumentException 配置非法
     */
    void configure(ResponseHeaderConfig config);

    /**
     * 改写响应头取值
     *
     * @param originalValue 原始取值，头缺失补充场景下为null
     * @return 新取值；返回null表示不改写
     */
    String transform(String originalValue);
}
