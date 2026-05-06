package top.oxff.model;

import top.oxff.service.PreferenceService;
import top.oxff.util.LanguageManager;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/**
 * 内置匹配关键词的表格模型
 */
public class BuiltinKeywordTableModel extends AbstractTableModel {

    private List<String> keywords;

    public BuiltinKeywordTableModel() {
        refreshData();
    }

    public void refreshData() {
        keywords = PreferenceService.getBuiltinKeywords();
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return keywords != null ? keywords.size() : 0;
    }

    @Override
    public int getColumnCount() {
        return 2;
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0:
                return LanguageManager.getString("pref.builtinKeywords.table.index");
            case 1:
                return LanguageManager.getString("pref.builtinKeywords.table.keyword");
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 1; // 只有关键词列可编辑
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (keywords == null || rowIndex < 0 || rowIndex >= keywords.size()) {
            return null;
        }
        switch (columnIndex) {
            case 0:
                return String.valueOf(rowIndex + 1);
            case 1:
                return keywords.get(rowIndex);
            default:
                return null;
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        if (columnIndex == 1 && aValue != null) {
            String oldKeyword = keywords.get(rowIndex);
            String newKeyword = aValue.toString().trim().toLowerCase();
            if (!oldKeyword.equals(newKeyword) && !newKeyword.isEmpty()) {
                PreferenceService.updateBuiltinKeyword(oldKeyword, newKeyword);
                refreshData();
            }
        }
    }

    public String getKeywordAt(int rowIndex) {
        if (keywords == null || rowIndex < 0 || rowIndex >= keywords.size()) {
            return null;
        }
        return keywords.get(rowIndex);
    }
}
