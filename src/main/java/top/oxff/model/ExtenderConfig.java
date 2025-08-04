package top.oxff.model;

import lombok.Data;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Data
public class ExtenderConfig {
    private Set<Integer> ToolFlags;
    private boolean proxyEnable;
    private boolean repeaterEnable;
    private boolean intruderEnable;
    private boolean scannerEnable;
    private boolean extenderEnable;
    private boolean popupMenuEnable;
    private List<HeaderItem> headerItemList;
    private Map<String, Integer> keyMap;
}