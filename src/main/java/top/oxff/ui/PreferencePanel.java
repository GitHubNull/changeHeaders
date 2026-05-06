package top.oxff.ui;

import top.oxff.service.PreferenceService;
import top.oxff.util.LanguageManager;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.nio.charset.StandardCharsets;

/**
 * 偏好管理主面板
 * 包含持久化键名和匹配关键词两个子Tab，以及导入导出按钮
 */
public class PreferencePanel extends JPanel {

    private JTabbedPane subTabbedPane;
    private PersistedKeyPanel persistedKeyPanel;
    private BuiltinKeywordPanel builtinKeywordPanel;
    private JButton exportBtn;
    private JButton importBtn;

    public PreferencePanel() {
        setLayout(new BorderLayout());

        // 子Tab面板
        subTabbedPane = new JTabbedPane();
        persistedKeyPanel = new PersistedKeyPanel();
        builtinKeywordPanel = new BuiltinKeywordPanel();

        subTabbedPane.addTab(LanguageManager.getString("tab.persistedKeys"), persistedKeyPanel);
        subTabbedPane.addTab(LanguageManager.getString("tab.builtinKeywords"), builtinKeywordPanel);

        add(subTabbedPane, BorderLayout.CENTER);

        // 底部导入导出按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        exportBtn = new JButton(LanguageManager.getString("button.exportPref"));
        importBtn = new JButton(LanguageManager.getString("button.importPref"));

        exportBtn.addActionListener(this::onExport);
        importBtn.addActionListener(this::onImport);

        buttonPanel.add(exportBtn);
        buttonPanel.add(importBtn);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void onExport(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle(LanguageManager.getString("dialog.exportPref.title"));
        fileChooser.setSelectedFile(new File("changeHeaders_prefs.yaml"));
        FileNameExtensionFilter filter = new FileNameExtensionFilter(
                LanguageManager.getString("dialog.filechooser.yamlFilter"), "yaml", "yml");
        fileChooser.setFileFilter(filter);

        int userSelection = fileChooser.showSaveDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();

            if (fileToSave == null || fileToSave.getName().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this,
                        LanguageManager.getString("error.file.empty"),
                        LanguageManager.getString("dialog.error.importPref.title"),
                        JOptionPane.ERROR_MESSAGE);
                return;
            }

            // 确保文件有.yaml扩展名
            if (!fileToSave.getAbsolutePath().endsWith(".yaml") && !fileToSave.getAbsolutePath().endsWith(".yml")) {
                fileToSave = new File(fileToSave + ".yaml");
            }

            try {
                String yamlContent = PreferenceService.exportPreferences();
                try (OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(fileToSave), StandardCharsets.UTF_8)) {
                    writer.write(yamlContent);
                }

                JOptionPane.showMessageDialog(this,
                        LanguageManager.getString("dialog.success.exportPref.message"),
                        LanguageManager.getString("dialog.success.exportPref.title"),
                        JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this,
                        LanguageManager.getString("dialog.error.importPref.message", ex.getMessage()),
                        LanguageManager.getString("dialog.error.importPref.title"),
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void onImport(ActionEvent e) {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle(LanguageManager.getString("dialog.importPref.title"));
        FileNameExtensionFilter filter = new FileNameExtensionFilter(
                LanguageManager.getString("dialog.filechooser.yamlFilter"), "yaml", "yml");
        fileChooser.setFileFilter(filter);

        int userSelection = fileChooser.showOpenDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();

            if (selectedFile == null || !selectedFile.exists()) {
                JOptionPane.showMessageDialog(this,
                        LanguageManager.getString("error.file.notExist"),
                        LanguageManager.getString("dialog.error.importPref.title"),
                        JOptionPane.ERROR_MESSAGE);
                return;
            }

            try {
                StringBuilder content = new StringBuilder();
                char[] buffer = new char[1024];
                int length;
                try (InputStreamReader reader = new InputStreamReader(new FileInputStream(selectedFile), StandardCharsets.UTF_8)) {
                    while ((length = reader.read(buffer)) != -1) {
                        content.append(buffer, 0, length);
                    }
                }

                // 确认导入
                int option = JOptionPane.showConfirmDialog(this,
                        LanguageManager.getString("dialog.confirm.importPref.message"),
                        LanguageManager.getString("dialog.importPref.title"),
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.WARNING_MESSAGE);

                if (option == JOptionPane.YES_OPTION) {
                    if (PreferenceService.importPreferences(content.toString())) {
                        persistedKeyPanel.updateUIText();
                        builtinKeywordPanel.updateUIText();

                        JOptionPane.showMessageDialog(this,
                                LanguageManager.getString("dialog.success.importPref.message"),
                                LanguageManager.getString("dialog.success.importPref.title"),
                                JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(this,
                                LanguageManager.getString("dialog.error.importPref.message", "Import failed"),
                                LanguageManager.getString("dialog.error.importPref.title"),
                                JOptionPane.ERROR_MESSAGE);
                    }
                }
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this,
                        LanguageManager.getString("dialog.error.importPref.message", ex.getMessage()),
                        LanguageManager.getString("dialog.error.importPref.title"),
                        JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public void updateUIText() {
        subTabbedPane.setTitleAt(0, LanguageManager.getString("tab.persistedKeys"));
        subTabbedPane.setTitleAt(1, LanguageManager.getString("tab.builtinKeywords"));
        exportBtn.setText(LanguageManager.getString("button.exportPref"));
        importBtn.setText(LanguageManager.getString("button.importPref"));
        persistedKeyPanel.updateUIText();
        builtinKeywordPanel.updateUIText();
    }
}
