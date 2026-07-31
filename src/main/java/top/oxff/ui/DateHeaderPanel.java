package top.oxff.ui;

import top.oxff.model.ResponseHeaderConfig;

/**
 * Date响应头改写设置子Tab面板
 * 控件与预览逻辑由 {@link HttpDateHeaderPanel} 提供，此处仅完成与 date* 配置字段的映射
 */
public class DateHeaderPanel extends HttpDateHeaderPanel {

    public DateHeaderPanel(Runnable changeCallback) {
        super(changeCallback, "response.date");
    }

    @Override
    public void fillConfig(ResponseHeaderConfig config) {
        config.setDateEnabled(isFieldEnabled());
        config.setDateFormatMode(currentFormatMode());
        config.setDatePattern(currentPattern());
        config.setDateZoneId(currentZoneId());
        config.setDateAddIfMissing(isAddIfMissing());
    }

    @Override
    public void loadFrom(ResponseHeaderConfig config) {
        if (null == config) {
            return;
        }

        loadCommon(config.isDateEnabled(), config.getDateFormatMode(), config.getDatePattern(),
                config.getDateZoneId(), config.isDateAddIfMissing());
        showPreview(config);
    }

    @Override
    public void showPreview(ResponseHeaderConfig config) {
        // Date表示报文生成时刻，预览无偏移
        renderPreview(config.getDateFormatMode(), config.getDatePattern(), config.getDateZoneId(), 0);
    }
}
