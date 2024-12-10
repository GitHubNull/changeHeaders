package top.oxff.model;

import javax.swing.table.AbstractTableModel;

public class HeaderItemTableModel extends AbstractTableModel {
    private final static String[] columnNames = new String[]{
            "Index", "Key", "Value", "Proxy", "Repeater", "Intruder", "Scanner", "Extender", "Description"
    };
    @Override
    public int getRowCount() {
        return 0;
    }

    @Override
    public int getColumnCount() {
        return 0;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        return null;
    }
}
