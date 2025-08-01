package top.oxff.ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import top.oxff.control.HeaderItemController;
import top.oxff.model.ExtenderConfig;
import top.oxff.model.HeaderItem;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
        
        exportConfigBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportConfig();
            }
        });
        
        importConfigBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                importConfig();
            }
        });

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
            
            // 确保文件有.json扩展名
            if (!fileToSave.getAbsolutePath().endsWith(".json")) {
                fileToSave = new File(fileToSave + ".json");
            }
            
            try {
                ExtenderConfig config = getExtenderConfig();
                // 序列化为JSON字符串
                String jsonString = com.alibaba.fastjson2.JSON.toJSONString(config);
                
                // 使用OutputStreamWriter以UTF-8编码写入文件
                try (OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(fileToSave), StandardCharsets.UTF_8)) {
                    writer.write(jsonString);
                }
                
                JOptionPane.showMessageDialog(this, "配置导出成功！", "导出成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "导出配置失败: " + ex.getMessage(), "导出失败", JOptionPane.ERROR_MESSAGE);
                ex.printStackTrace();
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
            
            try {
                // 使用InputStreamReader以UTF-8编码读取文件
                StringBuilder jsonString = new StringBuilder();
                char[] buffer = new char[1024];
                int length;
                try (InputStreamReader reader = new InputStreamReader(new FileInputStream(selectedFile), StandardCharsets.UTF_8)) {
                    while ((length = reader.read(buffer)) != -1) {
                        jsonString.append(buffer, 0, length);
                    }
                }
                
                ExtenderConfig config = com.alibaba.fastjson2.JSON.parseObject(jsonString.toString(), ExtenderConfig.class);
                
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
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "导入配置失败: " + ex.getMessage(), "导入失败", JOptionPane.ERROR_MESSAGE);
                ex.printStackTrace();
            }
        }
    }
    
    /**
     * 应用导入的配置
     * @param config 导入的配置
     */
    private void applyConfig(ExtenderConfig config) {
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
                // 使用HeaderItem对象直接添加行
                tableModel.addRow(item);
            }
        }
        
        // 设置键映射
        if (config.getKeyMap() != null) {
            tableModel.setKeyMap(config.getKeyMap());
        }
    }
}
