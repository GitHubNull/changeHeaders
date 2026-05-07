package top.oxff.ui;

import top.oxff.model.HeaderItemTableModel;

import javax.swing.RowFilter;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * 请求头表格行过滤器
 * 支持简单搜索和高级搜索（列选择、大小写敏感、正则表达式）
 */
public class HeaderRowFilter extends RowFilter<HeaderItemTableModel, Integer> {

    private String searchText = "";
    // 搜索列：0=全部, 1=Key, 2=Value, 9=Description
    private int searchColumn = 0;
    private boolean caseSensitive = false;
    private boolean regexMode = false;

    // 列索引常量
    private static final int COL_KEY = 1;
    private static final int COL_VALUE = 2;
    private static final int COL_DESCRIPTION = 9;

    @Override
    public boolean include(Entry<? extends HeaderItemTableModel, ? extends Integer> entry) {
        if (searchText == null || searchText.isEmpty()) {
            return true;
        }

        int[] columnsToSearch;
        switch (searchColumn) {
            case 1: // Key
                columnsToSearch = new int[]{COL_KEY};
                break;
            case 2: // Value
                columnsToSearch = new int[]{COL_VALUE};
                break;
            case 3: // Description
                columnsToSearch = new int[]{COL_DESCRIPTION};
                break;
            default: // All
                columnsToSearch = new int[]{COL_KEY, COL_VALUE, COL_DESCRIPTION};
                break;
        }

        for (int col : columnsToSearch) {
            Object value = entry.getModel().getValueAt(entry.getIdentifier(), col);
            if (value == null) continue;
            String cellText = value.toString();

            if (regexMode) {
                try {
                    int flags = caseSensitive ? 0 : Pattern.CASE_INSENSITIVE;
                    Pattern pattern = Pattern.compile(searchText, flags);
                    if (pattern.matcher(cellText).find()) {
                        return true;
                    }
                } catch (PatternSyntaxException e) {
                    // 正则表达式无效时不匹配，但不抛异常
                    return false;
                }
            } else {
                String search = caseSensitive ? searchText : searchText.toLowerCase();
                String cell = caseSensitive ? cellText : cellText.toLowerCase();
                if (cell.contains(search)) {
                    return true;
                }
            }
        }

        return false;
    }

    public void setSearchText(String searchText) {
        this.searchText = searchText;
    }

    /**
     * 设置搜索列
     * @param searchColumn 0=全部, 1=Key, 2=Value, 3=Description
     */
    public void setSearchColumn(int searchColumn) {
        this.searchColumn = searchColumn;
    }

    public void setCaseSensitive(boolean caseSensitive) {
        this.caseSensitive = caseSensitive;
    }

    public void setRegexMode(boolean regexMode) {
        this.regexMode = regexMode;
    }
}
