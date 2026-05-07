package top.oxff.util;

import burp.BurpExtender;
import top.oxff.model.HeaderItem;
import top.oxff.service.PreferenceMatcher;
import top.oxff.service.PreferenceService;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.util.*;
import java.util.List;
import java.util.function.Consumer;

/**
 * 右键替换头导入工具类
 * 用于从剪贴板导入HTTP请求头,并自动设置为右键手动替换模式
 */
public class PopupMenuHeaderImporter {
    
    /**
     * 从剪贴板导入右键替换头
     * @param parentComponent 父级组件
     * @param callback 回调函数，用于处理用户选择的请求头
     */
    public static void importFromClipboard(Component parentComponent, 
                                           Consumer<List<HeaderItem>> callback) {
        try {
            // 获取系统剪贴板
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            
            // 检查剪贴板中是否包含文本内容
            if (!clipboard.isDataFlavorAvailable(DataFlavor.stringFlavor)) {
                JOptionPane.showMessageDialog(parentComponent,
                    LanguageManager.getString("error.clipboard.empty"),
                    LanguageManager.getString("dialog.error.import.title"),
                    JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            // 获取剪贴板中的文本内容
            String clipboardText = (String) clipboard.getData(DataFlavor.stringFlavor);
            
            if (clipboardText == null || clipboardText.trim().isEmpty()) {
                JOptionPane.showMessageDialog(parentComponent,
                    LanguageManager.getString("error.clipboard.empty"),
                    LanguageManager.getString("dialog.error.import.title"),
                    JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            // 解析HTTP请求头
            List<HeaderItem> headerItems = parseHttpHeadersAsPopupMenu(clipboardText);
            
            if (headerItems.isEmpty()) {
                JOptionPane.showMessageDialog(parentComponent,
                    LanguageManager.getString("error.clipboard.noHeaders"),
                    LanguageManager.getString("dialog.error.import.title"),
                    JOptionPane.WARNING_MESSAGE);
                return;
            }

            // 使用PreferenceMatcher确定自动勾选的请求头（与ClipboardImporter逻辑一致）
            List<String> candidateKeys = new ArrayList<>();
            for (HeaderItem item : headerItems) {
                candidateKeys.add(item.getKey());
            }
            Set<String> autoSelectedKeys;
            if (PreferenceService.isInitialized()) {
                List<String> persistedKeys = PreferenceService.getPersistedHeaderKeys();
                List<String> builtinKeywords = PreferenceService.getBuiltinKeywords();
                autoSelectedKeys = PreferenceMatcher.determineAutoSelectedKeys(candidateKeys, persistedKeys, builtinKeywords);
            } else {
                autoSelectedKeys = Collections.emptySet();
            }

            // 显示选择对话框
            showHeaderSelectionDialog(parentComponent, headerItems, callback, autoSelectedKeys);
            
        } catch (UnsupportedFlavorException e) {
            JOptionPane.showMessageDialog(parentComponent,
                LanguageManager.getString("error.clipboard.format"),
                LanguageManager.getString("dialog.error.import.title"),
                JOptionPane.ERROR_MESSAGE);
            BurpExtender.logError(e.getMessage());
        } catch (Exception e) {
            JOptionPane.showMessageDialog(parentComponent,
                LanguageManager.getString("dialog.error.import.message", e.getMessage()),
                LanguageManager.getString("dialog.error.import.title"),
                JOptionPane.ERROR_MESSAGE);
            BurpExtender.logError(e.getMessage());
        }
    }
    
    /**
     * 解析HTTP请求头文本,并设置为右键替换模式
     * @param text HTTP请求头文本
     * @return 解析出的HeaderItem列表
     */
    private static List<HeaderItem> parseHttpHeadersAsPopupMenu(String text) {
        List<HeaderItem> headerItems = new ArrayList<>();
        
        // 按行分割文本
        String[] lines;
        if (text.contains("\r\n")) {
            lines = text.split("\r\n");
        } else if (text.contains("\n")) {
            lines = text.split("\n");
        } else {
            lines = new String[]{text};
        }
        
        // 解析每一行
        for (String line : lines) {
            // 跳过空行
            if (line.trim().isEmpty()) {
                continue;
            }
            
            // 跳过HTTP请求行（如 GET /path HTTP/1.1）
            if (line.startsWith("GET ") || line.startsWith("POST ") || line.startsWith("PUT ") || 
                line.startsWith("DELETE ") || line.startsWith("HEAD ") || line.startsWith("OPTIONS ") ||
                line.startsWith("PATCH ") || line.startsWith("TRACE ")) {
                continue;
            }
            
            // 解析请求头（格式：Key: Value）
            if (line.contains(":")) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    String key = parts[0].trim();
                    String value = parts[1].trim();
                    
                    if (!key.isEmpty()) {
                        HeaderItem headerItem = new HeaderItem();
                        headerItem.setKey(key);
                        headerItem.setValue(value);
                        
                        // 设置为右键手动替换模式：只启用popupMenu,其他模块全部禁用
                        headerItem.setProxyEnable(false);
                        headerItem.setRepeaterEnable(false);
                        headerItem.setIntruderEnable(false);
                        headerItem.setScannerEnable(false);
                        headerItem.setExtenderEnable(false);
                        headerItem.setPopupMenuEnable(true);
                        
                        // 默认不持久化
                        headerItem.setPersistent(false);
                        
                        headerItem.setDescription("");
                        
                        headerItems.add(headerItem);
                    }
                }
            }
        }
        
        return headerItems;
    }
    
    /**
     * 显示请求头选择对话框
     * @param parentComponent 父级组件
     * @param headerItems 可选择的请求头列表
     * @param callback 回调函数，用于处理用户选择的请求头
     * @param autoSelectedKeys 自动勾选的键名集合
     */
    private static void showHeaderSelectionDialog(Component parentComponent, 
                                                  List<HeaderItem> headerItems, 
                                                  Consumer<List<HeaderItem>> callback,
                                                  Set<String> autoSelectedKeys) {
        // 创建对话框（parentComponent为null时创建无父窗口的对话框）
        Window ownerWindow = parentComponent != null ? SwingUtilities.getWindowAncestor(parentComponent) : null;
        JDialog dialog = new JDialog(ownerWindow, 
                                   LanguageManager.getString("dialog.popupMenuSelection.title"), 
                                   Dialog.ModalityType.APPLICATION_MODAL);
        
        // 创建主面板
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // 创建说明标签
        JLabel infoLabel = new JLabel(LanguageManager.getString("dialog.popupMenuSelection.info"));
        infoLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        mainPanel.add(infoLabel, BorderLayout.NORTH);
        
        // 创建表格展示请求头
        String[] columnNames = {
            LanguageManager.getString("dialog.headerSelection.table.selected"),
            LanguageManager.getString("dialog.headerSelection.table.key"),
            LanguageManager.getString("dialog.headerSelection.table.value")
        };
        
        // 创建数据
        Object[][] data = new Object[headerItems.size()][3];

        // 使用偏好匹配确定自动勾选
        Set<String> matchedKeys;
        if (autoSelectedKeys != null) {
            matchedKeys = autoSelectedKeys;
        } else {
            // 如果没有传入，则实时从数据库获取偏好进行匹配
            List<String> candidateKeys = new ArrayList<>();
            for (HeaderItem item : headerItems) {
                candidateKeys.add(item.getKey());
            }
            List<String> persistedKeys = PreferenceService.isInitialized() ? PreferenceService.getPersistedHeaderKeys() : Collections.<String>emptyList();
            List<String> builtinKeywords = PreferenceService.isInitialized() ? PreferenceService.getBuiltinKeywords() : Collections.<String>emptyList();
            matchedKeys = PreferenceMatcher.determineAutoSelectedKeys(candidateKeys, persistedKeys, builtinKeywords);
        }

        for (int i = 0; i < headerItems.size(); i++) {
            HeaderItem item = headerItems.get(i);
            data[i][0] = matchedKeys.contains(item.getKey());
            data[i][1] = item.getKey();
            data[i][2] = item.getValue();
        }
        
        JTable table = new JTable(data, columnNames) {
            @Override
            public Class<?> getColumnClass(int column) {
                if (column == 0) {
                    return Boolean.class;
                }
                return String.class;
            }
            
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0; // 只有选择列可编辑
            }
        };
        
        table.setRowHeight(25);
        table.getTableHeader().setReorderingAllowed(false);
        
        // 设置选择列的宽度
        table.getColumnModel().getColumn(0).setPreferredWidth(50);
        table.getColumnModel().getColumn(0).setMaxWidth(50);
        
        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setPreferredSize(new Dimension(500, 300));
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        
        // 创建按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        
        JButton selectAllButton = new JButton(LanguageManager.getString("button.selectAll"));
        JButton deselectAllButton = new JButton(LanguageManager.getString("button.deselectAll"));
        JButton confirmButton = new JButton(LanguageManager.getString("button.confirm"));
        JButton cancelButton = new JButton(LanguageManager.getString("button.cancel"));

        selectAllButton.addActionListener(e -> {
            for (int i = 0; i < table.getRowCount(); i++) {
                table.setValueAt(true, i, 0);
            }
        });

        deselectAllButton.addActionListener(e -> {
            for (int i = 0; i < table.getRowCount(); i++) {
                table.setValueAt(false, i, 0);
            }
        });
        
        confirmButton.addActionListener(e -> {
            // 收集选中的请求头
            List<HeaderItem> selectedItems = new ArrayList<>();
            for (int i = 0; i < table.getRowCount(); i++) {
                Boolean isSelected = (Boolean) table.getValueAt(i, 0);
                if (isSelected) {
                    HeaderItem originalItem = headerItems.get(i);
                    HeaderItem newItem = cloneHeaderItem(originalItem);
                    selectedItems.add(newItem);
                }
            }

            // 持久化选中的请求头键名
            if (PreferenceService.isInitialized()) {
                for (HeaderItem item : selectedItems) {
                    PreferenceService.addPersistedHeaderKey(item.getKey());
                }
            }

            // 调用回调函数处理选中的请求头
            if (!selectedItems.isEmpty()) {
                callback.accept(selectedItems);
            }
            dialog.dispose();
        });
        
        cancelButton.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(selectAllButton);
        buttonPanel.add(deselectAllButton);
        buttonPanel.add(confirmButton);
        buttonPanel.add(cancelButton);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.getContentPane().add(mainPanel);
        dialog.pack();
        dialog.setResizable(false);
        dialog.setLocationRelativeTo(ownerWindow);
        dialog.setVisible(true);
    }
    
    /**
     * 克隆HeaderItem对象
     * @param original 原始HeaderItem
     * @return 克隆的HeaderItem
     */
    private static HeaderItem cloneHeaderItem(HeaderItem original) {
        HeaderItem clone = new HeaderItem();
        clone.setKey(original.getKey());
        clone.setValue(original.getValue());
        clone.setProxyEnable(original.isProxyEnable());
        clone.setRepeaterEnable(original.isRepeaterEnable());
        clone.setIntruderEnable(original.isIntruderEnable());
        clone.setScannerEnable(original.isScannerEnable());
        clone.setExtenderEnable(original.isExtenderEnable());
        clone.setPopupMenuEnable(original.isPopupMenuEnable());
        clone.setDescription(original.getDescription());
        clone.setPersistent(original.isPersistent());
        return clone;
    }
}
