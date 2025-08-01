package top.oxff.ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import top.oxff.control.HeaderItemController;
import top.oxff.model.ExtenderConfig;
//import com.sun.org.apache.xpath.internal.operations.String;

import javax.swing.*;
import java.awt.*;

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

        optPanel1.add(addBtn);
        optPanel1.add(delBtn);

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
}
