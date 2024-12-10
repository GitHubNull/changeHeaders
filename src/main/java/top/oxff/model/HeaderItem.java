package top.oxff.model;

import lombok.Data;

@Data
public class HeaderItem {
    int id;
    String key;
    String value;
    boolean proxyEnable;
    boolean repeaterEnable;
    boolean intruderEnable;
    boolean scannerEnable;
    boolean extenderEnable;
    String description;
}
