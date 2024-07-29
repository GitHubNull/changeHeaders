package top.oxff.util;

public class RowItem {
    String headerKey;
    String headerValue;
    String enable;
    String desc;

    public RowItem(String headerKey, String headerValue, String enable, String desc) {
        this.headerKey = headerKey;
        this.headerValue = headerValue;
        this.enable = enable;
        this.desc = desc;
    }

    public String getHeaderKey() {
        return headerKey;
    }

    public void setHeaderKey(String headerKey) {
        this.headerKey = headerKey;
    }

    public String getHeaderValue() {
        return headerValue;
    }

    public String getEnable() {
        return enable;
    }

    public void setEnable(String enable) {
        this.enable = enable;
    }

    public String getDesc() {
        return desc;
    }

    public void setDesc(String desc) {
        this.desc = desc;
    }
}
