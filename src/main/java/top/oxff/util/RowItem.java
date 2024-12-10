package top.oxff.util;

import lombok.Getter;

@Getter
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
}
