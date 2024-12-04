package top.oxff.ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import top.oxff.util.RowItem;
//import com.sun.org.apache.xpath.internal.operations.String;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TabUI extends JPanel {
    JPanel northPanel;
    JLabel label;

    JCheckBox proxyCheckbox;
    JCheckBox repeatCheckbox;
    JCheckBox intruderCheckbox;

    // for IBurpExtenderCallbacks.TOOL_EXTENDER
    JCheckBox extenderCheckbox;

    JScrollPane centerPanel;

    String[] tableHeader = new String[]{"键", "值", "是/否生效", "描述"};

    JTable table;

    DefaultTableModel tableModel;

    JPanel southPanel;

    JPanel optPanel1;

    JButton addBtn;
    JButton delBtn;

    JPanel optPanel2;

    JButton enableBtn;
    JButton disableBtn;

    public TabUI() {
        setLayout(new BorderLayout());

        northPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        label = new JLabel("生效模块");

        proxyCheckbox = new JCheckBox("proxy");

        repeatCheckbox = new JCheckBox("repeat");

        intruderCheckbox = new JCheckBox("intruder");

        extenderCheckbox = new JCheckBox("extender");

        northPanel.add(label);
        northPanel.add(proxyCheckbox);
        northPanel.add(repeatCheckbox);
        northPanel.add(intruderCheckbox);
        northPanel.add(extenderCheckbox);

        proxyCheckbox.addActionListener(e -> {
            if (proxyCheckbox.isSelected()) {
                BurpExtender.Tool_flags.add(IBurpExtenderCallbacks.TOOL_PROXY);
            } else {
                BurpExtender.Tool_flags.remove(IBurpExtenderCallbacks.TOOL_PROXY);
            }
        });

        repeatCheckbox.addActionListener(e -> {
            if (repeatCheckbox.isSelected()) {
                BurpExtender.Tool_flags.add(IBurpExtenderCallbacks.TOOL_REPEATER);
            } else {
                BurpExtender.Tool_flags.remove(IBurpExtenderCallbacks.TOOL_REPEATER);
            }
        });

        intruderCheckbox.addActionListener(e -> {
            if (intruderCheckbox.isSelected()) {
                BurpExtender.Tool_flags.add(IBurpExtenderCallbacks.TOOL_INTRUDER);
            } else {
                BurpExtender.Tool_flags.remove(IBurpExtenderCallbacks.TOOL_INTRUDER);
            }
        });

        extenderCheckbox.addActionListener(e-> {
            if (extenderCheckbox.isSelected()) {
                BurpExtender.Tool_flags.add(IBurpExtenderCallbacks.TOOL_EXTENDER);
            } else {
                BurpExtender.Tool_flags.remove(IBurpExtenderCallbacks.TOOL_EXTENDER);
            }
        });

        add(northPanel, BorderLayout.NORTH);


        table = new JTable();

        tableModel = new DefaultTableModel() {
            public boolean isCellEditable(int row, int col) {
                return col != 2;
            }
        };

        tableModel.setColumnIdentifiers(tableHeader);

        tableModel.addTableModelListener(e -> {

            if(tableModel.getRowCount() <= 0){
                return;
            }

            Map<String, String> tmpKvs = new HashMap<>();

            for (int i = 0; i < tableModel.getRowCount(); i++) {
                String k = (String) tableModel.getValueAt(i, 0);
                String v = (String) tableModel.getValueAt(i, 1);
                String enable = (String) tableModel.getValueAt(i, 2);

                if(null == enable || (!enable.equals("是")) || (null == k || null == v || k.trim().isEmpty() || v.trim().isEmpty())){
                    continue;
                }

                tmpKvs.put(k.trim(), v.trim());

            }
            BurpExtender.KVS.clear();
            BurpExtender.KVS.putAll(tmpKvs);


        });

        table.setModel(tableModel);

        table.addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = table.getSelectedRow();
                int col = table.getSelectedColumn();

                if (e.getClickCount() != 2 || col != 2) {
                    return;
                }

                String oldEnable = (String) tableModel.getValueAt(row, 2);
                String newEnable = oldEnable.equals("是") ? "否" : "是";

                tableModel.setValueAt(newEnable, row, col);
            }

            @Override
            public void mousePressed(MouseEvent e) {

            }

            @Override
            public void mouseReleased(MouseEvent e) {

            }

            @Override
            public void mouseEntered(MouseEvent e) {

            }

            @Override
            public void mouseExited(MouseEvent e) {

            }
        });


        centerPanel = new JScrollPane(table, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        add(centerPanel, BorderLayout.CENTER);

        southPanel = new JPanel(new BorderLayout());

        optPanel1 = new JPanel(new FlowLayout(FlowLayout.CENTER));

        addBtn = new JButton("新增");
        delBtn = new JButton("删除");

        addBtn.addActionListener(e -> {
            String[] item = new String[]{"", "", "是/否", ""};
            tableModel.addRow(item);
        });

        delBtn.addActionListener(e -> {
            int[] selectedRows = table.getSelectedRows();
            if (null == selectedRows || 0 == selectedRows.length) {
                return;
            }

            for (int selectedRow : selectedRows) {
                tableModel.removeRow(selectedRow);
                SwingUtilities.invokeLater(() -> tableModel.fireTableDataChanged());

                String k = (String) tableModel.getValueAt(selectedRow, 0);
                if (null != k && !k.isEmpty()){
                    BurpExtender.KVS.remove(k);
                }


            }
        });

        optPanel1.add(addBtn);
        optPanel1.add(delBtn);

        southPanel.add(optPanel1, BorderLayout.CENTER);

        optPanel2 = new JPanel(new FlowLayout(FlowLayout.CENTER));

        enableBtn = new JButton("生效");
        disableBtn = new JButton("失效");

        enableBtn.addActionListener(e -> {
            int[] selectedRows = table.getSelectedRows();
            if (null == selectedRows || 0 == selectedRows.length) {
                return;
            }

            for (int selectedRow : selectedRows) {
                tableModel.setValueAt("是", selectedRow, 2);
            }
        });

        disableBtn.addActionListener(e -> {
            int[] selectedRows = table.getSelectedRows();
            if (null == selectedRows || 0 == selectedRows.length) {
                return;
            }

            for (int selectedRow : selectedRows) {
                tableModel.setValueAt("否", selectedRow, 2);
            }
        });

        optPanel2.add(enableBtn);
        optPanel2.add(disableBtn);

        southPanel.add(optPanel2, BorderLayout.SOUTH);

        add(southPanel, BorderLayout.SOUTH);

    }

    public RowItem getRowItemByKey(String key) {
        int cnt = tableModel.getRowCount();
        if (cnt <= 0) {
            return null;
        }

        for (int i = 0; i < cnt; i++) {
            String k = (String) tableModel.getValueAt(i, 0);
            if (k.equals(key)) {
                String v = (String) tableModel.getValueAt(i, 1);
                String ev = (String) tableModel.getValueAt(i, 2);
                String dv = (String) tableModel.getValueAt(i, 3);

                return new RowItem(k, v, ev, dv);
            }
        }

        return null;
    }

    public List<RowItem> getRowItems() {
        List<RowItem> rowItems = new ArrayList<>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            rowItems.add(new RowItem((String) tableModel.getValueAt(i, 0), (String) tableModel.getValueAt(i, 1), (String) tableModel.getValueAt(i, 2), (String) tableModel.getValueAt(i, 3)));
        }

        return rowItems;
    }

    public void addRow(RowItem rowItem) {
        tableModel.addRow(new String[]{rowItem.getHeaderKey(), rowItem.getHeaderValue(), rowItem.getEnable(), rowItem.getDesc()});
    }

    public void updateRowByKey(RowItem rowItem) {
        int cnt = tableModel.getRowCount();
        for (int i = 0; i < cnt; i++) {
            String k = (String) tableModel.getValueAt(i, 0);
            if (k.equals(rowItem.getHeaderKey())) {
                tableModel.setValueAt(rowItem.getHeaderValue(), i, 1);
                tableModel.setValueAt(rowItem.getEnable(), i, 2);
                tableModel.setValueAt(rowItem.getDesc(), i, 3);

                return;
            }
        }
    }

    public void setCheckBoxStatus(int tool_flag, boolean status) {
        switch (tool_flag) {
            case IBurpExtenderCallbacks.TOOL_PROXY:
                proxyCheckbox.setSelected(status);
                break;
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                repeatCheckbox.setSelected(status);
                break;
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                intruderCheckbox.setSelected(status);
                break;
            default:
                break;
        }
    }
}
