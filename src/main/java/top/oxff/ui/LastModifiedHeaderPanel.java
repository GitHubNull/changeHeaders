package top.oxff.ui;

import top.oxff.model.ResponseHeaderConfig;

import javax.swing.*;
import java.awt.*;

/**
 * Last-Modified响应头改写设置子Tab面板
 * 除公共配置项外额外提供“补充偏移”，用于在响应缺失Last-Modified时按当前时间加偏移生成修改时刻
 */
public class LastModifiedHeaderPanel extends HttpDateHeaderPanel {

    /**
     * 偏移分钟数的取值范围：正负一年
     */
    private static final int OFFSET_LIMIT_MINUTES = 525600;

    private JLabel offsetLabel;
    private JSpinner offsetSpinner;
    private JLabel offsetUnitLabel;

    public LastModifiedHeaderPanel(Runnable changeCallback) {
        super(changeCallback, "response.lastModified");
    }

    @Override
    public void fillConfig(ResponseHeaderConfig config) {
        config.setLastModifiedEnabled(isFieldEnabled());
        config.setLastModifiedFormatMode(currentFormatMode());
        config.setLastModifiedPattern(currentPattern());
        config.setLastModifiedZoneId(currentZoneId());
        config.setLastModifiedAddIfMissing(isAddIfMissing());
        config.setLastModifiedOffsetMinutes(currentOffsetMinutes());
    }

    @Override
    public void loadFrom(ResponseHeaderConfig config) {
        if (null == config) {
            return;
        }

        offsetSpinner.setValue(config.getLastModifiedOffsetMinutes());
        loadCommon(config.isLastModifiedEnabled(), config.getLastModifiedFormatMode(), config.getLastModifiedPattern(),
                config.getLastModifiedZoneId(), config.isLastModifiedAddIfMissing());
        showPreview(config);
    }

    @Override
    public void showPreview(ResponseHeaderConfig config) {
        // 预览直接体现缺失补充场景的取值：当前时间加偏移
        renderPreview(config.getLastModifiedFormatMode(), config.getLastModifiedPattern(),
                config.getLastModifiedZoneId(), config.getLastModifiedOffsetMinutes());
    }

    @Override
    public void updateUIText() {
        super.updateUIText();
        offsetLabel.setText(text("offset.label"));
        offsetUnitLabel.setText(text("offset.unit"));
    }

    @Override
    protected void addExtraRows(JPanel contentPanel) {
        offsetLabel = new JLabel(text("offset.label"));
        offsetSpinner = new JSpinner(new SpinnerNumberModel(
                ResponseHeaderConfig.DEFAULT_LAST_MODIFIED_OFFSET_MINUTES, -OFFSET_LIMIT_MINUTES, OFFSET_LIMIT_MINUTES, 5));
        offsetSpinner.setPreferredSize(new Dimension(100, offsetSpinner.getPreferredSize().height));
        offsetSpinner.addChangeListener(e -> onChanged());
        offsetUnitLabel = new JLabel(text("offset.unit"));
        contentPanel.add(rowOf(offsetLabel, offsetSpinner, offsetUnitLabel));
    }

    @Override
    protected void refreshEnabledState() {
        super.refreshEnabledState();
        // addExtraRows 在基类构造期间被调用，首次刷新时偏移控件可能尚未创建
        if (null == offsetSpinner) {
            return;
        }
        boolean offsetEnabled = isFieldEnabled() && isAddIfMissing();
        offsetLabel.setEnabled(offsetEnabled);
        offsetSpinner.setEnabled(offsetEnabled);
        offsetUnitLabel.setEnabled(offsetEnabled);
    }

    private int currentOffsetMinutes() {
        Object value = offsetSpinner.getValue();
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return ResponseHeaderConfig.DEFAULT_LAST_MODIFIED_OFFSET_MINUTES;
    }
}
