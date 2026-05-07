package top.oxff.ui;

import top.oxff.model.HeaderItem;
import top.oxff.util.LanguageManager;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

/**
 * 请求头新增/编辑弹窗
 */
public class HeaderItemDialog extends JDialog {

    private HeaderItem result;
    private final boolean isEditMode;

    private JTextField keyField;
    private JTextArea valueArea;
    private JCheckBox proxyCheckbox;
    private JCheckBox repeaterCheckbox;
    private JCheckBox intruderCheckbox;
    private JCheckBox scannerCheckbox;
    private JCheckBox extenderCheckbox;
    private JCheckBox popupMenuCheckbox;
    private JTextArea descriptionArea;
    private JCheckBox persistentCheckbox;
    private JButton okButton;
    private JButton cancelButton;

    private HeaderItemDialog(Window owner, boolean isEditMode, HeaderItem existingItem) {
        super(owner,
                isEditMode ? LanguageManager.getString("dialog.headerEdit.title") : LanguageManager.getString("dialog.headerAdd.title"),
                ModalityType.APPLICATION_MODAL);
        this.isEditMode = isEditMode;
        this.result = null;

        initComponents(existingItem);
        layoutComponents();
        setupListeners();

        pack();
        setMinimumSize(new Dimension(450, 400));
        setLocationRelativeTo(owner);
        getRootPane().setDefaultButton(okButton);
    }

    private void initComponents(HeaderItem existingItem) {
        keyField = new JTextField(25);
        valueArea = new JTextArea(5, 25);
        valueArea.setLineWrap(true);
        valueArea.setWrapStyleWord(true);

        proxyCheckbox = new JCheckBox("Proxy");
        repeaterCheckbox = new JCheckBox("Repeater");
        intruderCheckbox = new JCheckBox("Intruder");
        scannerCheckbox = new JCheckBox("Scanner");
        extenderCheckbox = new JCheckBox("Extender");
        popupMenuCheckbox = new JCheckBox("PopupMenu");

        descriptionArea = new JTextArea(3, 25);
        descriptionArea.setLineWrap(true);
        descriptionArea.setWrapStyleWord(true);

        persistentCheckbox = new JCheckBox(LanguageManager.getString("dialog.headerItem.persistent"));

        okButton = new JButton(LanguageManager.getString("button.confirm"));
        cancelButton = new JButton(LanguageManager.getString("button.cancel"));

        // 编辑模式：预填数据
        if (existingItem != null) {
            keyField.setText(existingItem.getKey());
            valueArea.setText(existingItem.getValue());
            proxyCheckbox.setSelected(existingItem.isProxyEnable());
            repeaterCheckbox.setSelected(existingItem.isRepeaterEnable());
            intruderCheckbox.setSelected(existingItem.isIntruderEnable());
            scannerCheckbox.setSelected(existingItem.isScannerEnable());
            extenderCheckbox.setSelected(existingItem.isExtenderEnable());
            popupMenuCheckbox.setSelected(existingItem.isPopupMenuEnable());
            descriptionArea.setText(existingItem.getDescription());
            persistentCheckbox.setSelected(existingItem.isPersistent());
        } else {
            // 新增模式：默认全部勾选工具
            proxyCheckbox.setSelected(true);
            repeaterCheckbox.setSelected(true);
            intruderCheckbox.setSelected(true);
            scannerCheckbox.setSelected(true);
            extenderCheckbox.setSelected(true);
            popupMenuCheckbox.setSelected(true);
            persistentCheckbox.setSelected(true);
        }
    }

    private void layoutComponents() {
        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(new EmptyBorder(12, 12, 12, 12));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(4, 4, 4, 4);

        // Key
        gbc.gridx = 0; gbc.gridy = 0;
        mainPanel.add(new JLabel(LanguageManager.getString("dialog.headerItem.key")), gbc);
        gbc.gridx = 1; gbc.gridy = 0; gbc.weightx = 1.0;
        mainPanel.add(keyField, gbc);

        // Value
        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0; gbc.anchor = GridBagConstraints.NORTHWEST;
        mainPanel.add(new JLabel(LanguageManager.getString("dialog.headerItem.value")), gbc);
        gbc.gridx = 1; gbc.gridy = 1; gbc.weightx = 1.0; gbc.anchor = GridBagConstraints.WEST;
        JScrollPane valueScroll = new JScrollPane(valueArea);
        mainPanel.add(valueScroll, gbc);

        // Tool Enables
        gbc.gridx = 0; gbc.gridy = 2; gbc.anchor = GridBagConstraints.NORTHWEST;
        mainPanel.add(new JLabel(LanguageManager.getString("dialog.headerItem.toolEnables")), gbc);
        gbc.gridx = 1; gbc.gridy = 2; gbc.anchor = GridBagConstraints.WEST;
        JPanel toolPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        toolPanel.add(proxyCheckbox);
        toolPanel.add(repeaterCheckbox);
        toolPanel.add(intruderCheckbox);
        toolPanel.add(scannerCheckbox);
        toolPanel.add(extenderCheckbox);
        toolPanel.add(popupMenuCheckbox);
        mainPanel.add(toolPanel, gbc);

        // Description
        gbc.gridx = 0; gbc.gridy = 3; gbc.anchor = GridBagConstraints.NORTHWEST;
        mainPanel.add(new JLabel(LanguageManager.getString("dialog.headerItem.description")), gbc);
        gbc.gridx = 1; gbc.gridy = 3; gbc.anchor = GridBagConstraints.WEST;
        JScrollPane descScroll = new JScrollPane(descriptionArea);
        mainPanel.add(descScroll, gbc);

        // Persistent
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2; gbc.anchor = GridBagConstraints.WEST;
        mainPanel.add(persistentCheckbox, gbc);

        // Buttons
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 2; gbc.anchor = GridBagConstraints.EAST;
        gbc.fill = GridBagConstraints.NONE;
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttonPanel.add(okButton);
        buttonPanel.add(cancelButton);
        mainPanel.add(buttonPanel, gbc);

        setContentPane(mainPanel);
    }

    private void setupListeners() {
        okButton.addActionListener(e -> onOk());
        cancelButton.addActionListener(e -> dispose());

        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                dispose();
            }
        });
    }

    private void onOk() {
        String key = keyField.getText().trim();
        if (key.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    LanguageManager.getString("error.headerKey.empty"),
                    LanguageManager.getString(isEditMode ? "dialog.headerEdit.title" : "dialog.headerAdd.title"),
                    JOptionPane.WARNING_MESSAGE);
            keyField.requestFocusInWindow();
            return;
        }

        HeaderItem item = new HeaderItem();
        item.setKey(key);
        item.setValue(valueArea.getText());
        item.setProxyEnable(proxyCheckbox.isSelected());
        item.setRepeaterEnable(repeaterCheckbox.isSelected());
        item.setIntruderEnable(intruderCheckbox.isSelected());
        item.setScannerEnable(scannerCheckbox.isSelected());
        item.setExtenderEnable(extenderCheckbox.isSelected());
        item.setPopupMenuEnable(popupMenuCheckbox.isSelected());
        item.setDescription(descriptionArea.getText());
        item.setPersistent(persistentCheckbox.isSelected());

        this.result = item;
        dispose();
    }

    /**
     * 显示新增请求头弹窗
     * @param parent 父组件
     * @return 新增的 HeaderItem，取消返回 null
     */
    public static HeaderItem showAddDialog(Component parent) {
        Window owner = parent != null ? SwingUtilities.getWindowAncestor(parent) : null;
        HeaderItemDialog dialog = new HeaderItemDialog(owner, false, null);
        dialog.setVisible(true);
        return dialog.result;
    }

    /**
     * 显示编辑请求头弹窗
     * @param parent 父组件
     * @param existingItem 已有的请求头数据
     * @return 修改后的 HeaderItem，取消返回 null
     */
    public static HeaderItem showEditDialog(Component parent, HeaderItem existingItem) {
        Window owner = parent != null ? SwingUtilities.getWindowAncestor(parent) : null;
        HeaderItemDialog dialog = new HeaderItemDialog(owner, true, existingItem);
        dialog.setVisible(true);
        return dialog.result;
    }
}
