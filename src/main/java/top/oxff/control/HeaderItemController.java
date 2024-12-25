package top.oxff.control;

import top.oxff.model.HeaderItem;
import top.oxff.service.HeaderItemService;

import java.util.List;
import java.util.Map;

public class HeaderItemController {
    public static int addHeaderItem(String key, String value, String description, boolean proxyEnable,
                                    boolean repeaterEnable, boolean intruderEnable, boolean scannerEnable,
                                    boolean extenderEnable) {
        HeaderItem headerItem = new HeaderItem();
        headerItem.setKey(key);
        headerItem.setValue(value);
        headerItem.setDescription(description);
        headerItem.setProxyEnable(proxyEnable);
        headerItem.setRepeaterEnable(repeaterEnable);
        headerItem.setIntruderEnable(intruderEnable);
        headerItem.setScannerEnable(scannerEnable);
        headerItem.setExtenderEnable(extenderEnable);
        return HeaderItemService.addHeaderItem(headerItem);
    }

    public static boolean deleteHeaderItemById(HeaderItem headerItem) {
        return HeaderItemService.deleteHeaderItemById(headerItem.getId());
    }

    public static boolean deleteHeaderItemById(int id) {
        return HeaderItemService.deleteHeaderItemById(id);
    }

    public static boolean deleteHeaderItemByIndex(int index) {
        return HeaderItemService.deleteHeaderItemByIndex(index);
    }

    public static boolean deleteHeaderItemByKey(String key) {
        return HeaderItemService.deleteHeaderItemByKey(key);
    }

    public static boolean updateHeaderItem(HeaderItem oldHeaderItem, String key, String value, String description, boolean proxyEnable,
                                           boolean repeaterEnable, boolean intruderEnable, boolean scannerEnable,
                                           boolean extenderEnable) {
        HeaderItem newHeaderItem = new HeaderItem();
        newHeaderItem.setId(oldHeaderItem.getId());
        newHeaderItem.setKey(key);
        newHeaderItem.setValue(value);
        newHeaderItem.setDescription(description);
        newHeaderItem.setProxyEnable(proxyEnable);
        newHeaderItem.setRepeaterEnable(repeaterEnable);
        newHeaderItem.setIntruderEnable(intruderEnable);
        newHeaderItem.setScannerEnable(scannerEnable);
        newHeaderItem.setExtenderEnable(extenderEnable);
        return HeaderItemService.updateHeaderItem(oldHeaderItem, newHeaderItem);
    }

    public static boolean updateHeaderItem(HeaderItem oldheaderItem, HeaderItem newHeaderItem) {
        return HeaderItemService.updateHeaderItem(oldheaderItem, newHeaderItem);
    }

    public static boolean enableProxy(boolean proxyEnable, HeaderItem oldHeaderItem) {
        HeaderItem newHeaderItem = new HeaderItem();
        newHeaderItem.setId(oldHeaderItem.getId());
        newHeaderItem.setKey(oldHeaderItem.getKey());
        newHeaderItem.setValue(oldHeaderItem.getValue());
        newHeaderItem.setProxyEnable(proxyEnable);
        newHeaderItem.setRepeaterEnable(oldHeaderItem.isRepeaterEnable());
        newHeaderItem.setIntruderEnable(oldHeaderItem.isIntruderEnable());
        newHeaderItem.setExtenderEnable(oldHeaderItem.isExtenderEnable());
        newHeaderItem.setScannerEnable(oldHeaderItem.isScannerEnable());
        newHeaderItem.setDescription(oldHeaderItem.getDescription());

        return HeaderItemService.updateHeaderItem(oldHeaderItem, newHeaderItem);
    }

    public static boolean enableRepeater(boolean repeaterEnable, HeaderItem oldHeaderItem) {
        HeaderItem newHeaderItem = new HeaderItem();
        newHeaderItem.setId(oldHeaderItem.getId());
        newHeaderItem.setKey(oldHeaderItem.getKey());
        newHeaderItem.setValue(oldHeaderItem.getValue());
        newHeaderItem.setProxyEnable(oldHeaderItem.isProxyEnable());
        newHeaderItem.setRepeaterEnable(repeaterEnable);
        newHeaderItem.setIntruderEnable(oldHeaderItem.isIntruderEnable());
        newHeaderItem.setExtenderEnable(oldHeaderItem.isExtenderEnable());
        newHeaderItem.setScannerEnable(oldHeaderItem.isScannerEnable());
        newHeaderItem.setDescription(oldHeaderItem.getDescription());

        return HeaderItemService.updateHeaderItem(oldHeaderItem, newHeaderItem);
    }

    public static boolean enableIntruder(boolean intruderEnable, HeaderItem oldHeaderItem) {
        HeaderItem newHeaderItem = new HeaderItem();
        newHeaderItem.setId(oldHeaderItem.getId());
        newHeaderItem.setKey(oldHeaderItem.getKey());
        newHeaderItem.setValue(oldHeaderItem.getValue());
        newHeaderItem.setProxyEnable(oldHeaderItem.isProxyEnable());
        newHeaderItem.setRepeaterEnable(oldHeaderItem.isRepeaterEnable());
        newHeaderItem.setIntruderEnable(intruderEnable);
        newHeaderItem.setExtenderEnable(oldHeaderItem.isExtenderEnable());
        newHeaderItem.setScannerEnable(oldHeaderItem.isScannerEnable());
        newHeaderItem.setDescription(oldHeaderItem.getDescription());

        return HeaderItemService.updateHeaderItem(oldHeaderItem, newHeaderItem);
    }

    public static boolean enableExtender(boolean extenderEnable, HeaderItem oldHeaderItem) {
        HeaderItem newHeaderItem = new HeaderItem();
        newHeaderItem.setId(oldHeaderItem.getId());
        newHeaderItem.setKey(oldHeaderItem.getKey());
        newHeaderItem.setValue(oldHeaderItem.getValue());
        newHeaderItem.setProxyEnable(oldHeaderItem.isProxyEnable());
        newHeaderItem.setRepeaterEnable(oldHeaderItem.isRepeaterEnable());
        newHeaderItem.setIntruderEnable(oldHeaderItem.isIntruderEnable());
        newHeaderItem.setExtenderEnable(extenderEnable);
        newHeaderItem.setScannerEnable(oldHeaderItem.isScannerEnable());
        newHeaderItem.setDescription(oldHeaderItem.getDescription());

        return HeaderItemService.updateHeaderItem(oldHeaderItem, newHeaderItem);
    }

    public static boolean enableScanner(boolean scannerEnable, HeaderItem oldHeaderItem) {
        HeaderItem newHeaderItem = new HeaderItem();
        newHeaderItem.setId(oldHeaderItem.getId());
        newHeaderItem.setKey(oldHeaderItem.getKey());
        newHeaderItem.setValue(oldHeaderItem.getValue());
        newHeaderItem.setProxyEnable(oldHeaderItem.isProxyEnable());
        newHeaderItem.setRepeaterEnable(oldHeaderItem.isRepeaterEnable());
        newHeaderItem.setIntruderEnable(oldHeaderItem.isIntruderEnable());
        newHeaderItem.setExtenderEnable(oldHeaderItem.isExtenderEnable());
        newHeaderItem.setScannerEnable(scannerEnable);
        newHeaderItem.setDescription(oldHeaderItem.getDescription());

        return HeaderItemService.updateHeaderItem(oldHeaderItem, newHeaderItem);
    }

    public static HeaderItem getHeaderItemById(int id) {
        return HeaderItemService.getHeaderItemById(id);
    }

    public static HeaderItem getHeaderItemByIndex(int id) {
        return HeaderItemService.getHeaderItemByIndex(id);
    }

    public static HeaderItem getHeaderItemByKey(String key) {
        return HeaderItemService.getHeaderItemByKey(key);
    }

    public static HeaderItem[] getHeaderItems() {
        return HeaderItemService.getHeaderItemList().toArray(new HeaderItem[0]);
    }

    public static void deleteAllHeaderItem() {
        HeaderItemService.clear();
    }

    public static int getHeaderItemCount() {
        return HeaderItemService.getHeaderItemListSize();
    }

    public static Object getHeaderItemValue(int rowIndex, int columnIndex) {
        HeaderItem headerItem = HeaderItemService.getHeaderItemByIndex(rowIndex);
        if (null == headerItem) {
            return null;
        }
        switch (columnIndex) {
            case 0:
                return headerItem.getId();
            case 1:
                return headerItem.getKey();
            case 2:
                return headerItem.getValue();
            case 3:
                return headerItem.isProxyEnable();
            case 4:
                return headerItem.isRepeaterEnable();
            case 5:
                return headerItem.isIntruderEnable();
            case 6:
                return headerItem.isScannerEnable();
            case 7:
                return headerItem.isExtenderEnable();
            case 8:
                return headerItem.getDescription();
            default:
                return null;
        }
    }

    public static List<HeaderItem> getHeaderItemList(){
    	return HeaderItemService.getHeaderItemList();
    }

    public static void setHeaderItemList(List<HeaderItem> headerItemList){
    	HeaderItemService.setHeaderItemList(headerItemList);
    }

    public static Map<String, Integer> getKeyMap(){
    	return HeaderItemService.getKeyMap();
    }

    public static void setKeyMap(Map<String, Integer> keyMap){
    	HeaderItemService.setKeyMap(keyMap);
    }

    public static void addHeaderItem(HeaderItem headerItem) {
        HeaderItemService.addHeaderItem(headerItem);
    }

    public boolean isExist(String key){
        return HeaderItemService.isExist(key);
    }

}
