package top.oxff.ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import top.oxff.control.HeaderItemController;
import top.oxff.model.ExtenderConfig;
import top.oxff.model.HeaderItem;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import static burp.BurpExtender.TOOL_FLAGS;
import static burp.BurpExtender.tableModel;

public class TabUI extends JPanel {
    JPanel northPanel;
    JLabel label;

    JCheckBox proxyCheckbox;
    JCheckBox repeatCheckbox;
    JCheckBox intruderCheckbox;
    JCheckBox scannerCheckbox;
    JCheckBox popupMenuCheckbox;

    // for IBurpExtenderCallbacks.TOOL_EXTENDER
    JCheckBox extenderCheckbox;

    JScrollPane centerPanel;

    JTable table;

    JPanel southPanel;

    JPanel optPanel1;

    JButton addBtn;
    JButton delBtn;

    JPanel optPanel2;

    JButton clearAllConfigBtn;
    
    // 添加导入导出按钮
    JButton exportConfigBtn;
    JButton importConfigBtn;

    public TabUI() {
        setLayout(new BorderLayout());

        northPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        label = new JLabel("生效模块");

        proxyCheckbox = new JCheckBox("proxy");

        repeatCheckbox = new JCheckBox("repeat");

        intruderCheckbox = new JCheckBox("intruder");

        scannerCheckbox = new JCheckBox("scanner");

        extenderCheckbox = new JCheckBox("extender");

        popupMenuCheckbox = new JCheckBox("popupMenu");

        northPanel.add(label);
        northPanel.add(proxyCheckbox);
        northPanel.add(repeatCheckbox);
        northPanel.add(intruderCheckbox);
        northPanel.add(scannerCheckbox);
        northPanel.add(extenderCheckbox);
        northPanel.add(popupMenuCheckbox);

        proxyCheckbox.addActionListener(e -> {
            if (proxyCheckbox.isSelected()) {
                BurpExtender.TOOL_FLAGS.add(IBurpExtenderCallbacks.TOOL_PROXY);
            } else {
                BurpExtender.TOOL_FLAGS.remove(IBurpExtenderCallbacks.TOOL_PROXY);
            }
        });

        repeatCheckbox.addActionListener(e -> {
            if (repeatCheckbox.isSelected()) {
                BurpExtender.TOOL_FLAGS.add(IBurpExtenderCallbacks.TOOL_REPEATER);
            } else {
                BurpExtender.TOOL_FLAGS.remove(IBurpExtenderCallbacks.TOOL_REPEATER);
            }
        });

        intruderCheckbox.addActionListener(e -> {
            if (intruderCheckbox.isSelected()) {
                BurpExtender.TOOL_FLAGS.add(IBurpExtenderCallbacks.TOOL_INTRUDER);
            } else {
                BurpExtender.TOOL_FLAGS.remove(IBurpExtenderCallbacks.TOOL_INTRUDER);
            }
        });

        scannerCheckbox.addActionListener(e -> {
            if (scannerCheckbox.isSelected()) {
                BurpExtender.TOOL_FLAGS.add(IBurpExtenderCallbacks.TOOL_SCANNER);
            }else {
                BurpExtender.TOOL_FLAGS.remove(IBurpExtenderCallbacks.TOOL_SCANNER);
            }
        });

        extenderCheckbox.addActionListener(e-> {
            if (extenderCheckbox.isSelected()) {
                BurpExtender.TOOL_FLAGS.add(IBurpExtenderCallbacks.TOOL_EXTENDER);
            } else {
                BurpExtender.TOOL_FLAGS.remove(IBurpExtenderCallbacks.TOOL_EXTENDER);
            }
        });

        popupMenuCheckbox.addActionListener(e -> {
            if (popupMenuCheckbox.isSelected()) {
                BurpExtender.TOOL_FLAGS.add(BurpExtender.TOOL_FLAG_POPUP_MENU);
            } else {
                BurpExtender.TOOL_FLAGS.remove(BurpExtender.TOOL_FLAG_POPUP_MENU);
            }
        });

        add(northPanel, BorderLayout.NORTH);


        table = new JTable();

        table.setModel(tableModel);

        centerPanel = new JScrollPane(table, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        add(centerPanel, BorderLayout.CENTER);

        southPanel = new JPanel(new BorderLayout());

        optPanel1 = new JPanel(new FlowLayout(FlowLayout.CENTER));

        addBtn = new JButton("新增");
        delBtn = new JButton("删除");

        addBtn.addActionListener(e -> {
            String[] item = new String[]{"键", "值", "描述", "是/否", "是/否","是/否","是/否","是/否","是/否"};
            tableModel.addRow(item);
        });

        delBtn.addActionListener(e -> {
            int[] selectedRows = table.getSelectedRows();
            if (null == selectedRows) {
                return;
            }

            for (int selectedRow : selectedRows) {
                tableModel.removeRow(selectedRow);
            }
        });
        
        // 添加导入导出按钮
        exportConfigBtn = new JButton("导出配置");
        importConfigBtn = new JButton("导入配置");
        
        exportConfigBtn.addActionListener(e -> exportConfig());
        
        importConfigBtn.addActionListener(e -> importConfig());

        optPanel1.add(addBtn);
        optPanel1.add(delBtn);
        optPanel1.add(exportConfigBtn);
        optPanel1.add(importConfigBtn);

        southPanel.add(optPanel1, BorderLayout.CENTER);

        optPanel2 = new JPanel(new FlowLayout(FlowLayout.CENTER));

        clearAllConfigBtn = new JButton("清除所有配置");

        clearAllConfigBtn.addActionListener(e -> {
            tableModel.clear();
            TOOL_FLAGS.clear();
            proxyCheckbox.setSelected(false);
            repeatCheckbox.setSelected(false);
            intruderCheckbox.setSelected(false);
            scannerCheckbox.setSelected(false);
            extenderCheckbox.setSelected(false);
            popupMenuCheckbox.setSelected(false);
        });

        optPanel2.add(clearAllConfigBtn);

        southPanel.add(optPanel2, BorderLayout.SOUTH);

        add(southPanel, BorderLayout.SOUTH);

    }

    public void setCheckBoxStatus(ExtenderConfig extenderConfig) {
        proxyCheckbox.setSelected(extenderConfig.isProxyEnable());
        repeatCheckbox.setSelected(extenderConfig.isRepeaterEnable());
        intruderCheckbox.setSelected(extenderConfig.isIntruderEnable());
        scannerCheckbox.setSelected(extenderConfig.isScannerEnable());
        extenderCheckbox.setSelected(extenderConfig.isExtenderEnable());
        popupMenuCheckbox.setSelected(extenderConfig.isPopupMenuEnable());
    }
    
    public ExtenderConfig getExtenderConfig() {
        ExtenderConfig extenderConfig = new ExtenderConfig();
        extenderConfig.setToolFlags(BurpExtender.TOOL_FLAGS);
        extenderConfig.setProxyEnable(proxyCheckbox.isSelected());
        extenderConfig.setRepeaterEnable(repeatCheckbox.isSelected());
        extenderConfig.setIntruderEnable(intruderCheckbox.isSelected());
        extenderConfig.setScannerEnable(scannerCheckbox.isSelected());
        extenderConfig.setExtenderEnable(extenderCheckbox.isSelected());
        extenderConfig.setPopupMenuEnable(popupMenuCheckbox.isSelected());
        extenderConfig.setHeaderItemList(HeaderItemController.getHeaderItemList());
        extenderConfig.setKeyMap(HeaderItemController.getKeyMap());

        return extenderConfig;
    }
    
    /**
     * 导出配置到JSON文件
     */
    private void exportConfig() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导出配置文件");
        fileChooser.setSelectedFile(new File("changeHeaders_config.json"));
        FileNameExtensionFilter filter = new FileNameExtensionFilter("JSON files", "json");
        fileChooser.setFileFilter(filter);
        
        int userSelection = fileChooser.showSaveDialog(this);
        
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            
            // 检查文件名是否为空
            if (fileToSave == null || fileToSave.getName().trim().isEmpty()) {
                JOptionPane.showMessageDialog(this, "文件名不能为空！", "导出失败", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            // 确保文件有.json扩展名
            if (!fileToSave.getAbsolutePath().endsWith(".json")) {
                fileToSave = new File(fileToSave + ".json");
            }
            
            // 检查文件是否可写
            if (fileToSave.exists() && !fileToSave.canWrite()) {
                JOptionPane.showMessageDialog(this, "无法写入文件: " + fileToSave.getAbsolutePath(), "导出失败", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            try {
                ExtenderConfig config = getExtenderConfig();
                
                // 检查配置是否为空
                if (config == null) {
                    JOptionPane.showMessageDialog(this, "当前没有可导出的配置！", "导出失败", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                // 序列化为JSON字符串
                String jsonString = com.alibaba.fastjson2.JSON.toJSONString(config);
                
                // 检查JSON字符串是否为空
                if (jsonString == null || jsonString.isEmpty()) {
                    JOptionPane.showMessageDialog(this, "配置序列化失败！", "导出失败", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                // 使用OutputStreamWriter以UTF-8编码写入文件
                try (OutputStreamWriter writer = new OutputStreamWriter(Files.newOutputStream(fileToSave.toPath()), StandardCharsets.UTF_8)) {
                    writer.write(jsonString);
                }
                
                JOptionPane.showMessageDialog(this, "配置导出成功！\n文件位置: " + fileToSave.getAbsolutePath(), "导出成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (SecurityException ex) {
                JOptionPane.showMessageDialog(this, "没有权限写入文件: " + ex.getMessage(), "导出失败", JOptionPane.ERROR_MESSAGE);
                BurpExtender.logError( ex.getLocalizedMessage());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "文件写入失败: " + ex.getMessage(), "导出失败", JOptionPane.ERROR_MESSAGE);
                BurpExtender.logError( ex.getLocalizedMessage());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "导出配置失败: " + ex.getMessage(), "导出失败", JOptionPane.ERROR_MESSAGE);
                BurpExtender.logError( ex.getLocalizedMessage());
            }
        }
    }
    
    /**
     * 从JSON文件导入配置
     */
    private void importConfig() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("导入配置文件");
        FileNameExtensionFilter filter = new FileNameExtensionFilter("JSON files", "json");
        fileChooser.setFileFilter(filter);
        
        int userSelection = fileChooser.showOpenDialog(this);
        
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            
            // 检查文件是否存在
            if (selectedFile == null || !selectedFile.exists()) {
                JOptionPane.showMessageDialog(this, "选择的文件不存在！", "导入失败", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            // 检查文件是否可读
            if (!selectedFile.canRead()) {
                JOptionPane.showMessageDialog(this, "无法读取文件: " + selectedFile.getAbsolutePath(), "导入失败", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            // 检查文件扩展名
            if (!selectedFile.getName().toLowerCase().endsWith(".json")) {
                int option = JOptionPane.showConfirmDialog(this,
                        "选择的文件不是JSON格式，是否继续导入？",
                        "文件格式警告",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.WARNING_MESSAGE);
                if (option != JOptionPane.YES_OPTION) {
                    return;
                }
            }
            
            // 检查文件大小（防止过大的文件）
            long fileSize = selectedFile.length();
            if (fileSize > 10 * 1024 * 1024) { // 10MB
                JOptionPane.showMessageDialog(this, "配置文件过大（超过10MB），无法导入！", "导入失败", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            try {
                // 使用InputStreamReader以UTF-8编码读取文件
                StringBuilder jsonString = new StringBuilder();
                char[] buffer = new char[1024];
                int length;
                try (InputStreamReader reader = new InputStreamReader(Files.newInputStream(selectedFile.toPath()), StandardCharsets.UTF_8)) {
                    while ((length = reader.read(buffer)) != -1) {
                        jsonString.append(buffer, 0, length);
                    }
                }
                
                // 检查读取的内容是否为空
                if (jsonString.toString().trim().isEmpty()) {
                    JOptionPane.showMessageDialog(this, "配置文件内容为空！", "导入失败", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                // 解析JSON
                ExtenderConfig config = com.alibaba.fastjson2.JSON.parseObject(jsonString.toString(), ExtenderConfig.class);
                
                // 检查解析结果
                if (config == null) {
                    JOptionPane.showMessageDialog(this, "配置文件格式错误，无法解析！", "导入失败", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                // 确认是否要导入配置
                int option = JOptionPane.showConfirmDialog(this, 
                    "导入配置将覆盖当前所有配置，是否继续？", 
                    "确认导入", 
                    JOptionPane.YES_NO_OPTION);
                
                if (option == JOptionPane.YES_OPTION) {
                    // 应用导入的配置
                    applyConfig(config);
                    JOptionPane.showMessageDialog(this, "配置导入成功！", "导入成功", JOptionPane.INFORMATION_MESSAGE);
                }
            } catch (SecurityException ex) {
                JOptionPane.showMessageDialog(this, "没有权限读取文件: " + ex.getMessage(), "导入失败", JOptionPane.ERROR_MESSAGE);
                BurpExtender.logError( ex.getLocalizedMessage());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "文件读取失败: " + ex.getMessage(), "导入失败", JOptionPane.ERROR_MESSAGE);
                BurpExtender.logError( ex.getLocalizedMessage());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "导入配置失败: " + ex.getMessage(), "导入失败", JOptionPane.ERROR_MESSAGE);
                BurpExtender.logError( ex.getLocalizedMessage());
            }
        }
    }
    
    /**
     * 应用导入的配置
     * @param config 导入的配置
     */
    private void applyConfig(ExtenderConfig config) {
        try {
            // 检查配置是否为空
            if (config == null) {
                JOptionPane.showMessageDialog(this, "导入的配置为空！", "导入失败", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            // 设置复选框状态
            setCheckBoxStatus(config);
            
            // 清空现有表格数据
            tableModel.clear();
            
            // 设置工具标志
            TOOL_FLAGS.clear();
            if (config.getToolFlags() != null) {
                TOOL_FLAGS.addAll(config.getToolFlags());
            }
            
            // 添加表项
            if (config.getHeaderItemList() != null) {
                for (HeaderItem item : config.getHeaderItemList()) {
                    // 检查HeaderItem是否为空
                    if (item != null) {
                        // 使用HeaderItem对象直接添加行
                        tableModel.addRow(item);
                    }
                }
            }
            
            // 设置键映射
            if (config.getKeyMap() != null) {
                tableModel.setKeyMap(config.getKeyMap());
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "应用配置时发生错误: " + ex.getMessage(), "导入失败", JOptionPane.ERROR_MESSAGE);
            BurpExtender.logError( ex.getLocalizedMessage());
        }
    }
}
