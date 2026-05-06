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
 * 剪贴板导入工具类
 * 用于从系统剪贴板导入HTTP请求头
 */
public class ClipboardImporter {
    
    /**
     * 从剪贴板导入请求头
     */
    public static void importFromClipboard(Component parentComponent, Consumer<List<HeaderItem>> callback) {
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
            
            // 解析HTTP请求头（使用偏好匹配确定自动勾选）
            Set<String> autoSelectedKeys = getAutoSelectedKeys();
            List<HeaderItem> headerItems = parseHttpHeaders(clipboardText, autoSelectedKeys);
            
            if (headerItems.isEmpty()) {
                JOptionPane.showMessageDialog(parentComponent,
                    LanguageManager.getString("error.clipboard.noHeaders"),
                    LanguageManager.getString("dialog.error.import.title"),
                    JOptionPane.WARNING_MESSAGE);
                return;
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
     * 解析HTTP请求头文本
     * @param text HTTP请求头文本
     * @return 解析出的HeaderItem列表
     */
    private static List<HeaderItem> parseHttpHeaders(String text, Set<String> autoSelectedKeys) {
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
                        
                        // 默认启用所有工具
                        headerItem.setProxyEnable(true);
                        headerItem.setRepeaterEnable(true);
                        headerItem.setIntruderEnable(true);
                        headerItem.setScannerEnable(true);
                        headerItem.setExtenderEnable(true);
                        
                        // 对于偏好匹配的请求头，默认启用popupMenu
                        if (isPreferenceMatchedHeader(key, autoSelectedKeys)) {
                            headerItem.setPopupMenuEnable(true);
                        } else {
                            headerItem.setPopupMenuEnable(false);
                        }
                        
                        // 通过剪贴板导入的请求头默认不持久化
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
     * 判断是否为常见的重要请求头（基于偏好匹配）
     * @param key 请求头键名
     * @return 是否为偏好匹配的请求头
     */
    private static boolean isPreferenceMatchedHeader(String key, Set<String> autoSelectedKeys) {
        return autoSelectedKeys.contains(key);
    }
    
    /**
     * 获取自动勾选的请求头键名集合
     */
    private static Set<String> getAutoSelectedKeys() {
        if (!PreferenceService.isInitialized()) {
            return Collections.emptySet();
        }
        List<String> persistedKeys = PreferenceService.getPersistedHeaderKeys();
        List<String> builtinKeywords = PreferenceService.getBuiltinKeywords();
        // 用空候选列表获取当前偏好数据，实际匹配在对话框显示时进行
        return new HashSet<>(persistedKeys); // 返回持久化key集合用于后续匹配
    }

    /**
     * 显示请求头选择对话框
     * @param parentComponent 父级组件
     * @param headerItems 解析出的请求头列表
     * @param callback 回调函数，用于处理用户选择的请求头
     */
    private static void showHeaderSelectionDialog(Component parentComponent, List<HeaderItem> headerItems, Consumer<List<HeaderItem>> callback) {
        showHeaderSelectionDialog(parentComponent, headerItems, callback, null);
    }

    /**
     * 显示请求头选择对话框
     * @param parentComponent 父级组件
     * @param headerItems 解析出的请求头列表
     * @param callback 回调函数，用于处理用户选择的请求头
     * @param autoSelectedKeys 自动勾选的键名集合，如果为null则使用偏好匹配计算
     */
    public static void showHeaderSelectionDialog(Component parentComponent, List<HeaderItem> headerItems, Consumer<List<HeaderItem>> callback, Set<String> autoSelectedKeys) {
        // 创建对话框
        JDialog dialog = new JDialog(SwingUtilities.getWindowAncestor(parentComponent), 
                                   LanguageManager.getString("dialog.headerSelection.title"), 
                                   Dialog.ModalityType.APPLICATION_MODAL);
        
        // 创建主面板
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // 创建说明标签
        JLabel infoLabel = new JLabel(LanguageManager.getString("dialog.headerSelection.info"));
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
        boolean[] selected = new boolean[headerItems.size()];

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
            selected[i] = matchedKeys.contains(item.getKey()); // 使用偏好匹配结果
            data[i][0] = selected[i];
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
        
        JButton confirmButton = new JButton(LanguageManager.getString("button.confirm"));
        JButton cancelButton = new JButton(LanguageManager.getString("button.cancel"));
        
        confirmButton.addActionListener(e -> {
            // 收集选中的请求头并添加到表格中
            List<HeaderItem> selectedItems = new ArrayList<>();
            for (int i = 0; i < table.getRowCount(); i++) {
                Boolean isSelected = (Boolean) table.getValueAt(i, 0);
                if (isSelected) {
                    selectedItems.add(headerItems.get(i));
                }
            }

            // 持久化选中的请求头键名
            if (PreferenceService.isInitialized()) {
                for (HeaderItem item : selectedItems) {
                    PreferenceService.addPersistedHeaderKey(item.getKey());
                }
            }

            // 调用回调函数处理选中的请求头
            callback.accept(selectedItems);
            dialog.dispose();
        });
        
        cancelButton.addActionListener(e -> dialog.dispose());
        
        buttonPanel.add(confirmButton);
        buttonPanel.add(cancelButton);
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.getContentPane().add(mainPanel);
        dialog.pack();
        dialog.setResizable(false);
        dialog.setLocationRelativeTo(SwingUtilities.getWindowAncestor(parentComponent));
        dialog.setVisible(true);
    }
}