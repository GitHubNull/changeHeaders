package top.oxff.ui;

import top.oxff.model.PersistedKeyTableModel;
import top.oxff.service.PreferenceService;
import top.oxff.util.LanguageManager;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;

/**
 * 持久化键名子Tab面板
 */
public class PersistedKeyPanel extends JPanel {

    private JTable table;
    private PersistedKeyTableModel tableModel;
    private JButton addBtn;
    private JButton delBtn;
    private JButton clearBtn;
    private JLabel label;

    public PersistedKeyPanel() {
        setLayout(new BorderLayout());

        // 标签
        label = new JLabel(LanguageManager.getString("pref.persistedKeys.label"));
        label.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        add(label, BorderLayout.NORTH);

        // 表格
        tableModel = new PersistedKeyTableModel();
        table = new JTable(tableModel);
        table.setRowHeight(25);
        table.getTableHeader().setReorderingAllowed(false);
        JScrollPane scrollPane = new JScrollPane(table);
        add(scrollPane, BorderLayout.CENTER);

        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        addBtn = new JButton(LanguageManager.getString("button.add"));
        delBtn = new JButton(LanguageManager.getString("button.delete"));
        clearBtn = new JButton(LanguageManager.getString("button.clearAllConfig"));

        addBtn.addActionListener(this::onAdd);
        delBtn.addActionListener(this::onDelete);
        clearBtn.addActionListener(this::onClear);

        buttonPanel.add(addBtn);
        buttonPanel.add(delBtn);
        buttonPanel.add(clearBtn);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void onAdd(ActionEvent e) {
        String key = JOptionPane.showInputDialog(this,
                LanguageManager.getString("pref.persistedKeys.add.prompt"),
                LanguageManager.getString("pref.persistedKeys.add.title"),
                JOptionPane.PLAIN_MESSAGE);
        if (key == null || key.trim().isEmpty()) return;

        if (PreferenceService.addPersistedHeaderKey(key.trim())) {
            tableModel.refreshData();
        } else {
            JOptionPane.showMessageDialog(this,
                    LanguageManager.getString("error.pref.duplicate"),
                    LanguageManager.getString("pref.persistedKeys.add.title"),
                    JOptionPane.WARNING_MESSAGE);
        }
    }

    private void onDelete(ActionEvent e) {
        int[] selectedRows = table.getSelectedRows();
        if (selectedRows == null || selectedRows.length == 0) return;

        for (int row : selectedRows) {
            String key = tableModel.getKeyAt(row);
            if (key != null) {
                PreferenceService.removePersistedHeaderKey(key);
            }
        }
        tableModel.refreshData();
    }

    private void onClear(ActionEvent e) {
        int option = JOptionPane.showConfirmDialog(this,
                LanguageManager.getString("pref.persistedKeys.clear.confirm"),
                LanguageManager.getString("button.clearAllConfig"),
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
        if (option == JOptionPane.YES_OPTION) {
            PreferenceService.clearPersistedHeaderKeys();
            tableModel.refreshData();
        }
    }

    public void updateUIText() {
        label.setText(LanguageManager.getString("pref.persistedKeys.label"));
        addBtn.setText(LanguageManager.getString("button.add"));
        delBtn.setText(LanguageManager.getString("button.delete"));
        clearBtn.setText(LanguageManager.getString("button.clearAllConfig"));
        tableModel.refreshData();
    }
}
