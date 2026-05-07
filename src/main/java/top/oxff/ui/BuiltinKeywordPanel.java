package top.oxff.ui;

import top.oxff.model.BuiltinKeywordTableModel;
import top.oxff.service.PreferenceService;
import top.oxff.util.LanguageManager;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;

/**
 * 内置匹配关键词子Tab面板
 */
public class BuiltinKeywordPanel extends JPanel {

    private JTable table;
    private BuiltinKeywordTableModel tableModel;
    private JButton addBtn;
    private JButton delBtn;
    private JButton editBtn;
    private JButton resetBtn;
    private JLabel label;

    public BuiltinKeywordPanel() {
        setLayout(new BorderLayout());

        // 标签
        label = new JLabel(LanguageManager.getString("pref.builtinKeywords.label"));
        label.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        add(label, BorderLayout.NORTH);

        // 表格
        tableModel = new BuiltinKeywordTableModel();
        table = new JTable(tableModel);
        table.setRowHeight(25);
        table.getTableHeader().setReorderingAllowed(false);
        JScrollPane scrollPane = new JScrollPane(table);
        add(scrollPane, BorderLayout.CENTER);

        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        addBtn = new JButton(LanguageManager.getString("button.add"));
        delBtn = new JButton(LanguageManager.getString("button.delete"));
        editBtn = new JButton(LanguageManager.getString("button.edit"));
        resetBtn = new JButton(LanguageManager.getString("button.resetDefaults"));

        addBtn.addActionListener(this::onAdd);
        delBtn.addActionListener(this::onDelete);
        editBtn.addActionListener(this::onEdit);
        resetBtn.addActionListener(this::onReset);

        buttonPanel.add(addBtn);
        buttonPanel.add(delBtn);
        buttonPanel.add(editBtn);
        buttonPanel.add(resetBtn);
        add(buttonPanel, BorderLayout.SOUTH);

        // 注册偏好数据变更监听器，自动刷新表格
        PreferenceService.addChangeListener(tableModel::refreshData);
    }

    private void onAdd(ActionEvent e) {
        String keyword = JOptionPane.showInputDialog(this,
                LanguageManager.getString("pref.builtinKeywords.add.prompt"),
                LanguageManager.getString("pref.builtinKeywords.add.title"),
                JOptionPane.PLAIN_MESSAGE);
        if (keyword == null || keyword.trim().isEmpty()) return;

        String lowerKeyword = keyword.trim().toLowerCase();
        if (!lowerKeyword.equals(keyword.trim())) {
            JOptionPane.showMessageDialog(this,
                    LanguageManager.getString("error.pref.keywordNotLowercase"),
                    LanguageManager.getString("pref.builtinKeywords.add.title"),
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (PreferenceService.addBuiltinKeyword(lowerKeyword)) {
            tableModel.refreshData();
        } else {
            JOptionPane.showMessageDialog(this,
                    LanguageManager.getString("error.pref.keywordDuplicate"),
                    LanguageManager.getString("pref.builtinKeywords.add.title"),
                    JOptionPane.WARNING_MESSAGE);
        }
    }

    private void onDelete(ActionEvent e) {
        int[] selectedRows = table.getSelectedRows();
        if (selectedRows == null || selectedRows.length == 0) return;

        for (int row : selectedRows) {
            String keyword = tableModel.getKeywordAt(row);
            if (keyword != null) {
                PreferenceService.removeBuiltinKeyword(keyword);
            }
        }
        tableModel.refreshData();
    }

    private void onEdit(ActionEvent e) {
        int selectedRow = table.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(this,
                    LanguageManager.getString("pref.builtinKeywords.edit.prompt"),
                    LanguageManager.getString("pref.builtinKeywords.edit.title"),
                    JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String oldKeyword = tableModel.getKeywordAt(selectedRow);
        if (oldKeyword == null) return;

        String newKeyword = (String) JOptionPane.showInputDialog(this,
                LanguageManager.getString("pref.builtinKeywords.edit.prompt"),
                LanguageManager.getString("pref.builtinKeywords.edit.title"),
                JOptionPane.PLAIN_MESSAGE, null, null, oldKeyword);
        if (newKeyword == null || newKeyword.trim().isEmpty()) return;

        String lowerNewKeyword = newKeyword.trim().toLowerCase();
        if (!lowerNewKeyword.equals(newKeyword.trim())) {
            JOptionPane.showMessageDialog(this,
                    LanguageManager.getString("error.pref.keywordNotLowercase"),
                    LanguageManager.getString("pref.builtinKeywords.edit.title"),
                    JOptionPane.WARNING_MESSAGE);
            return;
        }

        if (PreferenceService.updateBuiltinKeyword(oldKeyword, lowerNewKeyword)) {
            tableModel.refreshData();
        } else {
            JOptionPane.showMessageDialog(this,
                    LanguageManager.getString("error.pref.keywordDuplicate"),
                    LanguageManager.getString("pref.builtinKeywords.edit.title"),
                    JOptionPane.WARNING_MESSAGE);
        }
    }

    private void onReset(ActionEvent e) {
        int option = JOptionPane.showConfirmDialog(this,
                LanguageManager.getString("pref.builtinKeywords.reset.confirm"),
                LanguageManager.getString("button.resetDefaults"),
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
        if (option == JOptionPane.YES_OPTION) {
            PreferenceService.resetBuiltinKeywordsToDefaults();
            tableModel.refreshData();
        }
    }

    public void updateUIText() {
        label.setText(LanguageManager.getString("pref.builtinKeywords.label"));
        addBtn.setText(LanguageManager.getString("button.add"));
        delBtn.setText(LanguageManager.getString("button.delete"));
        editBtn.setText(LanguageManager.getString("button.edit"));
        resetBtn.setText(LanguageManager.getString("button.resetDefaults"));
        tableModel.refreshData();
    }
}
