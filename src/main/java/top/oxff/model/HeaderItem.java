package top.oxff.model;

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
    String description;

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
            default:
                return false;
        }
    }
}
