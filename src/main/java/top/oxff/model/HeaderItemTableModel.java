package top.oxff.model;

import top.oxff.control.HeaderItemController;

import javax.swing.table.AbstractTableModel;
import java.util.List;
import java.util.Map;

public class HeaderItemTableModel extends AbstractTableModel {
    private final static String[] columnNames = new String[]{
            "Index", "Key", "Value", "Proxy", "Repeater", "Intruder", "Scanner", "Extender", "Description"
    };
    private final static Class[] columnClasses = new Class[]{
            Integer.class, String.class, String.class, Boolean.class, Boolean.class, Boolean.class, Boolean.class,
            Boolean.class, String.class
    };


    public void clear() {
        HeaderItemController.deleteAllHeaderItem();
        fireTableDataChanged();
    }

    public void setHeaderItemList(List<HeaderItem> headerItemList) {
        HeaderItemController.setHeaderItemList(headerItemList);
    }

    public void setKeyMap(Map<String, Integer> keyMap) {
        HeaderItemController.setKeyMap(keyMap);
    }

    public Map<String, Integer> getKeyMap() {
        return HeaderItemController.getKeyMap();
    }

    @Override
    public int getRowCount() {
        return HeaderItemController.getHeaderItemCount();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        return HeaderItemController.getHeaderItemValue(rowIndex, columnIndex);
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return columnClasses[columnIndex];
    }

    public boolean isCellEditable(int row, int column) {
        return column != 0;
    }

    public void addRow(String[] item) {
        HeaderItemController.addHeaderItem(
                item[0],
                item[1],
                item[2],
                "是".equals(item[3]),
                "是".equals(item[3]),
                "是".equals(item[3]),
                "是".equals(item[3]),
                "是".equals(item[3])
        );
        fireTableRowsInserted(getRowCount() - 1, getRowCount() - 1);
    }

    public void addRow(HeaderItem headerItem) {
        HeaderItemController.addHeaderItem(headerItem);
        fireTableRowsInserted(getRowCount() - 1, getRowCount() - 1);
    }

    public void removeRow(int selectedRow) {
        HeaderItemController.deleteHeaderItemByIndex(selectedRow);
        fireTableRowsDeleted(selectedRow, selectedRow);
    }

    public void updateRow(int rowIndex, HeaderItem headerItem) {
        HeaderItemController.updateHeaderItem(HeaderItemController.getHeaderItemByIndex(rowIndex), headerItem);
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex <= 0 || columnIndex >= columnClasses.length || rowIndex >= getRowCount() || null == aValue) {
            return;
        }
        HeaderItem oldHeaderItem = HeaderItemController.getHeaderItemByIndex(rowIndex);
        switch (columnIndex) {
            case 1:
                HeaderItemController.updateHeaderItem(oldHeaderItem, (String) aValue, oldHeaderItem.getValue(), oldHeaderItem.getDescription(), oldHeaderItem.isProxyEnable(), oldHeaderItem.isRepeaterEnable(), oldHeaderItem.isIntruderEnable(), oldHeaderItem.isScannerEnable(), oldHeaderItem.isExtenderEnable());
                fireTableCellUpdated(rowIndex, columnIndex);
                break;
            case 2:
                HeaderItemController.updateHeaderItem(oldHeaderItem, oldHeaderItem.getKey(), (String) aValue, oldHeaderItem.getDescription(), oldHeaderItem.isProxyEnable(), oldHeaderItem.isRepeaterEnable(), oldHeaderItem.isIntruderEnable(), oldHeaderItem.isScannerEnable(), oldHeaderItem.isExtenderEnable());
                fireTableCellUpdated(rowIndex, columnIndex);
                break;
            case 3:
                HeaderItemController.enableProxy((Boolean) aValue, oldHeaderItem);
                fireTableCellUpdated(rowIndex, columnIndex);
                break;
            case 4:
                HeaderItemController.enableRepeater((Boolean) aValue, oldHeaderItem);
                fireTableCellUpdated(rowIndex, columnIndex);
                break;
            case 5:
                HeaderItemController.enableIntruder((Boolean) aValue, oldHeaderItem);
                fireTableCellUpdated(rowIndex, columnIndex);
                break;
            case 6:
                HeaderItemController.enableScanner((boolean) aValue, oldHeaderItem);
                fireTableCellUpdated(rowIndex, columnIndex);
                break;
            case 7:
                HeaderItemController.enableExtender((boolean) aValue, oldHeaderItem);
                fireTableCellUpdated(rowIndex, columnIndex);
                break;
            default:
                break;
        }
    }

    public boolean isEmpty() {
        return HeaderItemController.getHeaderItemCount() == 0;
    }

    public boolean isExist(String key) {
        return HeaderItemController.getHeaderItemByKey(key) != null;
    }

    public HeaderItem getHeaderItemByKey(String key) {
        return HeaderItemController.getHeaderItemByKey(key);
    }

    public String getValueByKey(String key) {
        return getHeaderItemByKey(key).getValue();
    }

    public List<HeaderItem> getHeaderItemList() {
        return HeaderItemController.getHeaderItemList();
    }

    public boolean isEnableTool(int toolFlag, String key) {
        HeaderItem headerItem = getHeaderItemByKey(key);
        if (headerItem == null){
            return false;
        }
        return headerItem.isEnableTool(toolFlag);
    }
}
