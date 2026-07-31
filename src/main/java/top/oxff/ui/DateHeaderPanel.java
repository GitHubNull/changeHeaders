package top.oxff.ui;

import top.oxff.model.DateHeaderSettings;
import top.oxff.model.ResponseHeaderConfig;
import top.oxff.util.LanguageManager;

import javax.swing.*;
import java.awt.*;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Date响应头改写设置子Tab面板
 * 负责格式模式、自定义格式、目标时区等配置项的采集与预览
 */
public class DateHeaderPanel extends JPanel {

    /**
     * 常用自定义格式预置项
     */
    private static final String[] PRESET_PATTERNS = new String[]{
            "yyyy-MM-dd HH:mm:ss",
            "yyyy/MM/dd HH:mm:ss",
            "dd/MM/yyyy HH:mm:ss",
            "yyyy年MM月dd日 HH:mm:ss",
            "EEE, dd MMM yyyy HH:mm:ss Z"
    };

    private final Runnable changeCallback;

    private JCheckBox enableCheckbox;
    private JLabel formatModeLabel;
    private JRadioButton rfc1123Radio;
    private JRadioButton customRadio;
    private JLabel patternLabel;
    private JComboBox<String> patternCombo;
    private JLabel zoneLabel;
    private JCheckBox useLocalZoneCheckbox;
    private JComboBox<String> zoneCombo;
    private JCheckBox addIfMissingCheckbox;
    private JLabel previewLabel;
    private JLabel previewValueLabel;

    /**
     * 回填控件期间抑制变更回调，避免递归触发
     */
    private boolean loading = false;

    public DateHeaderPanel(Runnable changeCallback) {
        this.changeCallback = changeCallback;

        setLayout(new BorderLayout());

        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // 启用开关
        enableCheckbox = new JCheckBox(LanguageManager.getString("response.date.enable"));
        contentPanel.add(rowOf(enableCheckbox));

        // 格式模式
        formatModeLabel = new JLabel(LanguageManager.getString("response.date.formatMode.label"));
        rfc1123Radio = new JRadioButton(LanguageManager.getString("response.date.formatMode.rfc1123"), true);
        customRadio = new JRadioButton(LanguageManager.getString("response.date.formatMode.custom"));
        ButtonGroup formatModeGroup = new ButtonGroup();
        formatModeGroup.add(rfc1123Radio);
        formatModeGroup.add(customRadio);
        contentPanel.add(rowOf(formatModeLabel, rfc1123Radio, customRadio));

        // 自定义格式
        patternLabel = new JLabel(LanguageManager.getString("response.date.pattern.label"));
        patternCombo = new JComboBox<>(PRESET_PATTERNS);
        patternCombo.setEditable(true);
        patternCombo.setPreferredSize(new Dimension(260, patternCombo.getPreferredSize().height));
        contentPanel.add(rowOf(patternLabel, patternCombo));

        // 目标时区
        zoneLabel = new JLabel(LanguageManager.getString("response.date.zone.label"));
        useLocalZoneCheckbox = new JCheckBox(LanguageManager.getString("response.date.zone.useLocal"), true);
        zoneCombo = new JComboBox<>(loadZoneIds());
        zoneCombo.setEditable(true);
        zoneCombo.setPreferredSize(new Dimension(260, zoneCombo.getPreferredSize().height));
        zoneCombo.setSelectedItem(ZoneId.systemDefault().getId());
        contentPanel.add(rowOf(zoneLabel, useLocalZoneCheckbox, zoneCombo));

        // 缺失时补充
        addIfMissingCheckbox = new JCheckBox(LanguageManager.getString("response.date.addIfMissing"));
        contentPanel.add(rowOf(addIfMissingCheckbox));

        // 预览
        previewLabel = new JLabel(LanguageManager.getString("response.date.preview.label"));
        previewValueLabel = new JLabel();
        contentPanel.add(rowOf(previewLabel, previewValueLabel));

        add(contentPanel, BorderLayout.NORTH);

        registerListeners();
        refreshEnabledState();
    }

    /**
     * 把面板上的配置项写入配置对象
     *
     * @param config 目标配置对象
     */
    public void fillConfig(ResponseHeaderConfig config) {
        config.setDateEnabled(enableCheckbox.isSelected());
        config.setDateFormatMode(customRadio.isSelected()
                ? ResponseHeaderConfig.FORMAT_MODE_CUSTOM : ResponseHeaderConfig.FORMAT_MODE_RFC1123);
        config.setDatePattern(currentPattern());
        config.setDateZoneId(useLocalZoneCheckbox.isSelected() ? null : currentZoneId());
        config.setDateAddIfMissing(addIfMissingCheckbox.isSelected());
    }

    /**
     * 用配置回填控件
     *
     * @param config 响应头配置
     */
    public void loadFrom(ResponseHeaderConfig config) {
        if (null == config) {
            return;
        }

        loading = true;
        try {
            enableCheckbox.setSelected(config.isDateEnabled());

            boolean custom = ResponseHeaderConfig.FORMAT_MODE_CUSTOM.equals(config.getDateFormatMode());
            customRadio.setSelected(custom);
            rfc1123Radio.setSelected(!custom);

            String pattern = config.getDatePattern();
            patternCombo.setSelectedItem(null == pattern || pattern.trim().isEmpty()
                    ? ResponseHeaderConfig.DEFAULT_DATE_PATTERN : pattern);

            String zoneId = config.getDateZoneId();
            boolean useLocal = null == zoneId || zoneId.trim().isEmpty();
            useLocalZoneCheckbox.setSelected(useLocal);
            zoneCombo.setSelectedItem(useLocal ? ZoneId.systemDefault().getId() : zoneId);

            addIfMissingCheckbox.setSelected(config.isDateAddIfMissing());
        } finally {
            loading = false;
        }

        refreshEnabledState();
        showPreview(config);
    }

    /**
     * 显示格式化预览（以当前时间为样例）
     *
     * @param config 已校验通过的配置
     */
    public void showPreview(ResponseHeaderConfig config) {
        try {
            ZoneId zone = DateHeaderSettings.resolveZone(config.getDateZoneId());
            previewValueLabel.setForeground(UIManager.getColor("Label.foreground"));
            previewValueLabel.setText(DateHeaderSettings.buildFormatter(config).format(ZonedDateTime.now(zone)));
        } catch (Exception e) {
            showPatternError(e.getMessage());
        }
    }

    /**
     * 显示自定义格式错误
     *
     * @param message 错误信息
     */
    public void showPatternError(String message) {
        previewValueLabel.setForeground(Color.RED);
        previewValueLabel.setText(LanguageManager.getString("error.response.date.pattern", message));
    }

    public void updateUIText() {
        enableCheckbox.setText(LanguageManager.getString("response.date.enable"));
        formatModeLabel.setText(LanguageManager.getString("response.date.formatMode.label"));
        rfc1123Radio.setText(LanguageManager.getString("response.date.formatMode.rfc1123"));
        customRadio.setText(LanguageManager.getString("response.date.formatMode.custom"));
        patternLabel.setText(LanguageManager.getString("response.date.pattern.label"));
        zoneLabel.setText(LanguageManager.getString("response.date.zone.label"));
        useLocalZoneCheckbox.setText(LanguageManager.getString("response.date.zone.useLocal"));
        addIfMissingCheckbox.setText(LanguageManager.getString("response.date.addIfMissing"));
        previewLabel.setText(LanguageManager.getString("response.date.preview.label"));
    }

    private void registerListeners() {
        enableCheckbox.addActionListener(e -> onChanged());
        rfc1123Radio.addActionListener(e -> onChanged());
        customRadio.addActionListener(e -> onChanged());
        addIfMissingCheckbox.addActionListener(e -> onChanged());
        useLocalZoneCheckbox.addActionListener(e -> onChanged());
        patternCombo.addActionListener(e -> onChanged());
        zoneCombo.addActionListener(e -> onChanged());
    }

    private void onChanged() {
        if (loading) {
            return;
        }
        refreshEnabledState();
        if (null != changeCallback) {
            changeCallback.run();
        }
    }

    /**
     * 根据当前选择刷新控件可用状态
     */
    private void refreshEnabledState() {
        boolean dateEnabled = enableCheckbox.isSelected();
        rfc1123Radio.setEnabled(dateEnabled);
        customRadio.setEnabled(dateEnabled);
        patternCombo.setEnabled(dateEnabled && customRadio.isSelected());
        useLocalZoneCheckbox.setEnabled(dateEnabled);
        zoneCombo.setEnabled(dateEnabled && !useLocalZoneCheckbox.isSelected());
        addIfMissingCheckbox.setEnabled(dateEnabled);
    }

    private String currentPattern() {
        Object selected = patternCombo.getSelectedItem();
        if (null == selected || selected.toString().trim().isEmpty()) {
            return ResponseHeaderConfig.DEFAULT_DATE_PATTERN;
        }
        return selected.toString().trim();
    }

    private String currentZoneId() {
        Object selected = zoneCombo.getSelectedItem();
        if (null == selected || selected.toString().trim().isEmpty()) {
            return ZoneId.systemDefault().getId();
        }
        return selected.toString().trim();
    }

    private static String[] loadZoneIds() {
        List<String> zoneIds = new ArrayList<>(ZoneId.getAvailableZoneIds());
        Collections.sort(zoneIds);
        return zoneIds.toArray(new String[0]);
    }

    private static JPanel rowOf(Component... components) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        for (Component component : components) {
            row.add(component);
        }
        return row;
    }
}
