package top.oxff.model;

import top.oxff.service.PreferenceService;
import top.oxff.util.LanguageManager;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/**
 * 持久化请求头键名的表格模型
 */
public class PersistedKeyTableModel extends AbstractTableModel {

    private List<String> keys;

    public PersistedKeyTableModel() {
        refreshData();
    }

    public void refreshData() {
        keys = PreferenceService.getPersistedHeaderKeys();
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return keys != null ? keys.size() : 0;
    }

    @Override
    public int getColumnCount() {
        return 2;
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0:
                return LanguageManager.getString("pref.persistedKeys.table.index");
            case 1:
                return LanguageManager.getString("pref.persistedKeys.table.key");
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (keys == null || rowIndex < 0 || rowIndex >= keys.size()) {
            return null;
        }
        switch (columnIndex) {
            case 0:
                return String.valueOf(rowIndex + 1);
            case 1:
                return keys.get(rowIndex);
            default:
                return null;
        }
    }

    public String getKeyAt(int rowIndex) {
        if (keys == null || rowIndex < 0 || rowIndex >= keys.size()) {
            return null;
        }
        return keys.get(rowIndex);
    }
}
