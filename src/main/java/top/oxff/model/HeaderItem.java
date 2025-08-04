package top.oxff.model;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
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
    boolean popupMenuEnable;
    String description;
    // 添加持久化控制字段，默认为true表示需要持久化
    boolean persistent = true;

    public boolean isEnableTool(int toolFlag) {
        switch (toolFlag) {
            case IBurpExtenderCallbacks.TOOL_PROXY:
                return proxyEnable;
            case IBurpExtenderCallbacks.TOOL_REPEATER:
                return repeaterEnable;
            case IBurpExtenderCallbacks.TOOL_INTRUDER:
                return intruderEnable;
            case IBurpExtenderCallbacks.TOOL_SCANNER:
                return scannerEnable;
            case IBurpExtenderCallbacks.TOOL_EXTENDER:
                return extenderEnable;
            case BurpExtender.TOOL_FLAG_POPUP_MENU:
                return popupMenuEnable;
            default:
                return false;
        }
    }
}