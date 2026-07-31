package top.oxff.ui;

import top.oxff.model.HttpDateHeaderSettings;
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
 * HTTP日期类响应头改写设置子Tab面板基类
 * 统一装配格式模式、自定义格式、目标时区、缺失补充与预览等公共控件，
 * 文案键由子类传入的前缀派生（如 response.date.enable），子类只负责与配置字段的映射
 */
public abstract class HttpDateHeaderPanel extends JPanel {

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

    /**
     * 文案键前缀，如 response.date / response.expires
     */
    private final String keyPrefix;

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

    protected HttpDateHeaderPanel(Runnable changeCallback, String keyPrefix) {
        this.changeCallback = changeCallback;
        this.keyPrefix = keyPrefix;

        setLayout(new BorderLayout());

        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        contentPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // 启用开关
        enableCheckbox = new JCheckBox(text("enable"));
        contentPanel.add(rowOf(enableCheckbox));

        // 格式模式
        formatModeLabel = new JLabel(text("formatMode.label"));
        rfc1123Radio = new JRadioButton(text("formatMode.rfc1123"), true);
        customRadio = new JRadioButton(text("formatMode.custom"));
        ButtonGroup formatModeGroup = new ButtonGroup();
        formatModeGroup.add(rfc1123Radio);
        formatModeGroup.add(customRadio);
        contentPanel.add(rowOf(formatModeLabel, rfc1123Radio, customRadio));

        // 自定义格式
        patternLabel = new JLabel(text("pattern.label"));
        patternCombo = new JComboBox<>(PRESET_PATTERNS);
        patternCombo.setEditable(true);
        patternCombo.setPreferredSize(new Dimension(260, patternCombo.getPreferredSize().height));
        contentPanel.add(rowOf(patternLabel, patternCombo));

        // 目标时区
        zoneLabel = new JLabel(text("zone.label"));
        useLocalZoneCheckbox = new JCheckBox(text("zone.useLocal"), true);
        zoneCombo = new JComboBox<>(loadZoneIds());
        zoneCombo.setEditable(true);
        zoneCombo.setPreferredSize(new Dimension(260, zoneCombo.getPreferredSize().height));
        zoneCombo.setSelectedItem(ZoneId.systemDefault().getId());
        contentPanel.add(rowOf(zoneLabel, useLocalZoneCheckbox, zoneCombo));

        // 缺失时补充
        addIfMissingCheckbox = new JCheckBox(text("addIfMissing"));
        contentPanel.add(rowOf(addIfMissingCheckbox));

        // 子类扩展行
        addExtraRows(contentPanel);

        // 预览
        previewLabel = new JLabel(text("preview.label"));
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
    public abstract void fillConfig(ResponseHeaderConfig config);

    /**
     * 用配置回填控件
     *
     * @param config 响应头配置
     */
    public abstract void loadFrom(ResponseHeaderConfig config);

    /**
     * 显示格式化预览（以当前时间为样例）
     *
     * @param config 响应头配置
     */
    public abstract void showPreview(ResponseHeaderConfig config);

    /**
     * 显示自定义格式错误
     *
     * @param message 错误信息
     */
    public void showPatternError(String message) {
        previewValueLabel.setForeground(Color.RED);
        previewValueLabel.setText(LanguageManager.getString("error." + keyPrefix + ".pattern", message));
    }

    public void updateUIText() {
        enableCheckbox.setText(text("enable"));
        formatModeLabel.setText(text("formatMode.label"));
        rfc1123Radio.setText(text("formatMode.rfc1123"));
        customRadio.setText(text("formatMode.custom"));
        patternLabel.setText(text("pattern.label"));
        zoneLabel.setText(text("zone.label"));
        useLocalZoneCheckbox.setText(text("zone.useLocal"));
        addIfMissingCheckbox.setText(text("addIfMissing"));
        previewLabel.setText(text("preview.label"));
    }

    /**
     * 子类在“缺失时补充”与“预览”之间插入自有配置行
     *
     * @param contentPanel 内容面板
     */
    protected void addExtraRows(JPanel contentPanel) {
    }

    /**
     * 用公共配置项回填公共控件
     *
     * @param enabled      是否启用改写
     * @param formatMode   输出格式模式
     * @param pattern      自定义格式
     * @param zoneId       目标时区ID，为空表示本地系统时区
     * @param addIfMissing 缺失时是否补充
     */
    protected void loadCommon(boolean enabled, String formatMode, String pattern,
                              String zoneId, boolean addIfMissing) {
        loading = true;
        try {
            enableCheckbox.setSelected(enabled);

            boolean custom = ResponseHeaderConfig.FORMAT_MODE_CUSTOM.equals(formatMode);
            customRadio.setSelected(custom);
            rfc1123Radio.setSelected(!custom);

            patternCombo.setSelectedItem(null == pattern || pattern.trim().isEmpty()
                    ? ResponseHeaderConfig.DEFAULT_DATE_PATTERN : pattern);

            boolean useLocal = null == zoneId || zoneId.trim().isEmpty();
            useLocalZoneCheckbox.setSelected(useLocal);
            zoneCombo.setSelectedItem(useLocal ? ZoneId.systemDefault().getId() : zoneId);

            addIfMissingCheckbox.setSelected(addIfMissing);
        } finally {
            loading = false;
        }

        refreshEnabledState();
    }

    /**
     * 渲染预览取值，失败时在预览行显示错误
     *
     * @param formatMode    输出格式模式
     * @param pattern       自定义格式
     * @param zoneId        目标时区ID
     * @param offsetMinutes 相对当前时间的偏移分钟数
     */
    protected void renderPreview(String formatMode, String pattern, String zoneId, int offsetMinutes) {
        try {
            ZoneId zone = HttpDateHeaderSettings.resolveZone(zoneId);
            ZonedDateTime sample = ZonedDateTime.now(zone).plusMinutes(offsetMinutes);
            previewValueLabel.setForeground(UIManager.getColor("Label.foreground"));
            previewValueLabel.setText(HttpDateHeaderSettings.buildFormatter(formatMode, pattern).format(sample));
        } catch (Exception e) {
            showPatternError(e.getMessage());
        }
    }

    /**
     * 根据当前选择刷新控件可用状态
     */
    protected void refreshEnabledState() {
        boolean fieldEnabled = enableCheckbox.isSelected();
        rfc1123Radio.setEnabled(fieldEnabled);
        customRadio.setEnabled(fieldEnabled);
        patternCombo.setEnabled(fieldEnabled && customRadio.isSelected());
        useLocalZoneCheckbox.setEnabled(fieldEnabled);
        zoneCombo.setEnabled(fieldEnabled && !useLocalZoneCheckbox.isSelected());
        addIfMissingCheckbox.setEnabled(fieldEnabled);
    }

    /**
     * 控件变更后刷新状态并回调宿主面板
     */
    protected void onChanged() {
        if (loading) {
            return;
        }
        refreshEnabledState();
        if (null != changeCallback) {
            changeCallback.run();
        }
    }

    protected boolean isFieldEnabled() {
        return enableCheckbox.isSelected();
    }

    protected boolean isAddIfMissing() {
        return addIfMissingCheckbox.isSelected();
    }

    protected String currentFormatMode() {
        return customRadio.isSelected()
                ? ResponseHeaderConfig.FORMAT_MODE_CUSTOM : ResponseHeaderConfig.FORMAT_MODE_RFC1123;
    }

    protected String currentPattern() {
        Object selected = patternCombo.getSelectedItem();
        if (null == selected || selected.toString().trim().isEmpty()) {
            return ResponseHeaderConfig.DEFAULT_DATE_PATTERN;
        }
        return selected.toString().trim();
    }

    /**
     * 当前选择的时区ID
     *
     * @return 勾选“使用本地系统时区”时返回null
     */
    protected String currentZoneId() {
        if (useLocalZoneCheckbox.isSelected()) {
            return null;
        }
        Object selected = zoneCombo.getSelectedItem();
        if (null == selected || selected.toString().trim().isEmpty()) {
            return ZoneId.systemDefault().getId();
        }
        return selected.toString().trim();
    }

    /**
     * 按前缀取本地化文案
     *
     * @param suffix 键后缀
     * @return 本地化文案
     */
    protected String text(String suffix) {
        return LanguageManager.getString(keyPrefix + "." + suffix);
    }

    protected static JPanel rowOf(Component... components) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        for (Component component : components) {
            row.add(component);
        }
        return row;
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

    private static String[] loadZoneIds() {
        List<String> zoneIds = new ArrayList<>(ZoneId.getAvailableZoneIds());
        Collections.sort(zoneIds);
        return zoneIds.toArray(new String[0]);
    }
}
