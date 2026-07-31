package top.oxff.ui;

import burp.IBurpExtenderCallbacks;
import top.oxff.model.ResponseHeaderConfig;
import top.oxff.service.ResponseHeaderService;
import top.oxff.util.LanguageManager;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 响应头管理主面板
 * 顶部为总开关与独立的生效工具勾选（与请求头管理的TOOL_FLAGS互不干扰），
 * 中部为各响应头字段的子Tab，后续新增字段只需新增子面板并addTab
 */
public class ResponseHeaderPanel extends JPanel {

    private JLabel toolsLabel;
    private JCheckBox enableCheckbox;
    private JCheckBox proxyCheckbox;
    private JCheckBox repeaterCheckbox;
    private JCheckBox intruderCheckbox;
    private JCheckBox scannerCheckbox;
    private JCheckBox extenderCheckbox;

    private JTabbedPane subTabbedPane;
    private DateHeaderPanel dateHeaderPanel;
    private ExpiresHeaderPanel expiresHeaderPanel;

    private JButton resetBtn;

    /**
     * 回填控件期间抑制变更回调
     */
    private boolean loading = false;

    public ResponseHeaderPanel() {
        setLayout(new BorderLayout());

        // 顶部：总开关 + 生效工具
        JPanel northPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        enableCheckbox = new JCheckBox(LanguageManager.getString("response.enable"));
        toolsLabel = new JLabel(LanguageManager.getString("response.tools.label"));
        proxyCheckbox = new JCheckBox(LanguageManager.getString("checkbox.proxy"));
        repeaterCheckbox = new JCheckBox(LanguageManager.getString("checkbox.repeat"));
        intruderCheckbox = new JCheckBox(LanguageManager.getString("checkbox.intruder"));
        scannerCheckbox = new JCheckBox(LanguageManager.getString("checkbox.scanner"));
        extenderCheckbox = new JCheckBox(LanguageManager.getString("checkbox.extender"));

        northPanel.add(enableCheckbox);
        northPanel.add(toolsLabel);
        northPanel.add(proxyCheckbox);
        northPanel.add(repeaterCheckbox);
        northPanel.add(intruderCheckbox);
        northPanel.add(scannerCheckbox);
        northPanel.add(extenderCheckbox);
        add(northPanel, BorderLayout.NORTH);

        // 中部：各响应头字段子Tab
        subTabbedPane = new JTabbedPane();
        dateHeaderPanel = new DateHeaderPanel(this::applyToService);
        subTabbedPane.addTab(LanguageManager.getString("tab.responseDate"), dateHeaderPanel);
        expiresHeaderPanel = new ExpiresHeaderPanel(this::applyToService);
        subTabbedPane.addTab(LanguageManager.getString("tab.responseExpires"), expiresHeaderPanel);
        add(subTabbedPane, BorderLayout.CENTER);

        // 底部：恢复默认
        JPanel southPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        resetBtn = new JButton(LanguageManager.getString("button.resetResponseDefaults"));
        resetBtn.addActionListener(this::onReset);
        southPanel.add(resetBtn);
        add(southPanel, BorderLayout.SOUTH);

        registerListeners();
        refreshEnabledState();
    }

    /**
     * 采集当前界面配置
     *
     * @return 响应头配置
     */
    public ResponseHeaderConfig buildConfig() {
        ResponseHeaderConfig config = new ResponseHeaderConfig();
        config.setEnabled(enableCheckbox.isSelected());
        config.setResponseToolFlags(collectToolFlags());
        dateHeaderPanel.fillConfig(config);
        expiresHeaderPanel.fillConfig(config);
        return config;
    }

    /**
     * 用配置回填界面（启动加载与导入配置时调用）
     *
     * @param config 响应头配置
     */
    public void loadFrom(ResponseHeaderConfig config) {
        if (null == config) {
            return;
        }

        loading = true;
        try {
            enableCheckbox.setSelected(config.isEnabled());

            Set<Integer> toolFlags = null == config.getResponseToolFlags()
                    ? new LinkedHashSet<>() : config.getResponseToolFlags();
            proxyCheckbox.setSelected(toolFlags.contains(IBurpExtenderCallbacks.TOOL_PROXY));
            repeaterCheckbox.setSelected(toolFlags.contains(IBurpExtenderCallbacks.TOOL_REPEATER));
            intruderCheckbox.setSelected(toolFlags.contains(IBurpExtenderCallbacks.TOOL_INTRUDER));
            scannerCheckbox.setSelected(toolFlags.contains(IBurpExtenderCallbacks.TOOL_SCANNER));
            extenderCheckbox.setSelected(toolFlags.contains(IBurpExtenderCallbacks.TOOL_EXTENDER));
        } finally {
            loading = false;
        }

        dateHeaderPanel.loadFrom(config);
        expiresHeaderPanel.loadFrom(config);
        refreshEnabledState();
    }

    public void updateUIText() {
        enableCheckbox.setText(LanguageManager.getString("response.enable"));
        toolsLabel.setText(LanguageManager.getString("response.tools.label"));
        proxyCheckbox.setText(LanguageManager.getString("checkbox.proxy"));
        repeaterCheckbox.setText(LanguageManager.getString("checkbox.repeat"));
        intruderCheckbox.setText(LanguageManager.getString("checkbox.intruder"));
        scannerCheckbox.setText(LanguageManager.getString("checkbox.scanner"));
        extenderCheckbox.setText(LanguageManager.getString("checkbox.extender"));
        resetBtn.setText(LanguageManager.getString("button.resetResponseDefaults"));
        subTabbedPane.setTitleAt(0, LanguageManager.getString("tab.responseDate"));
        subTabbedPane.setTitleAt(1, LanguageManager.getString("tab.responseExpires"));
        dateHeaderPanel.updateUIText();
        expiresHeaderPanel.updateUIText();

        // 语言变化会影响自定义格式的输出，重新提交一次配置并刷新预览
        applyToService();
    }

    /**
     * 提交界面配置到服务层，校验失败时保留上一次生效的配置并提示
     */
    private void applyToService() {
        if (loading) {
            return;
        }

        ResponseHeaderConfig config = buildConfig();
        try {
            ResponseHeaderService.applyConfig(config);
        } catch (Exception ignored) {
            // 校验失败时保留上一次生效的配置，非法格式由对应子面板的预览行提示
        }

        // 每个子面板独立渲染预览，避免一个字段的非法格式污染另一个字段的预览
        dateHeaderPanel.showPreview(config);
        expiresHeaderPanel.showPreview(config);
    }

    private void registerListeners() {
        enableCheckbox.addActionListener(e -> onChanged());
        proxyCheckbox.addActionListener(e -> onChanged());
        repeaterCheckbox.addActionListener(e -> onChanged());
        intruderCheckbox.addActionListener(e -> onChanged());
        scannerCheckbox.addActionListener(e -> onChanged());
        extenderCheckbox.addActionListener(e -> onChanged());
    }

    private void onChanged() {
        refreshEnabledState();
        applyToService();
    }

    private void onReset(ActionEvent e) {
        loadFrom(ResponseHeaderService.resetDefaults());
    }

    /**
     * 总开关关闭时置灰工具勾选与子面板
     */
    private void refreshEnabledState() {
        boolean enabled = enableCheckbox.isSelected();
        toolsLabel.setEnabled(enabled);
        proxyCheckbox.setEnabled(enabled);
        repeaterCheckbox.setEnabled(enabled);
        intruderCheckbox.setEnabled(enabled);
        scannerCheckbox.setEnabled(enabled);
        extenderCheckbox.setEnabled(enabled);
    }

    private Set<Integer> collectToolFlags() {
        Set<Integer> toolFlags = new LinkedHashSet<>();
        if (proxyCheckbox.isSelected()) {
            toolFlags.add(IBurpExtenderCallbacks.TOOL_PROXY);
        }
        if (repeaterCheckbox.isSelected()) {
            toolFlags.add(IBurpExtenderCallbacks.TOOL_REPEATER);
        }
        if (intruderCheckbox.isSelected()) {
            toolFlags.add(IBurpExtenderCallbacks.TOOL_INTRUDER);
        }
        if (scannerCheckbox.isSelected()) {
            toolFlags.add(IBurpExtenderCallbacks.TOOL_SCANNER);
        }
        if (extenderCheckbox.isSelected()) {
            toolFlags.add(IBurpExtenderCallbacks.TOOL_EXTENDER);
        }
        return toolFlags;
    }
}
