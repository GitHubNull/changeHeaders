package top.oxff.service;

import top.oxff.model.HeaderItem;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class HeaderItemService {
//    private static HeaderItemService instance;
    private static final List<HeaderItem> headerItemList = new ArrayList<>();

    synchronized public static int addHeaderItem(HeaderItem headerItem) {
        headerItem.setId(headerItemList.size());
        headerItemList.add(headerItem);
        return headerItem.getId();
    }

    synchronized public static boolean deleteHeaderItemById(int id) {
        if (id < 0 || id >= headerItemList.size()) {
            return false; // 或者抛出异常
        }
        Iterator<HeaderItem> iterator = headerItemList.iterator();
        while (iterator.hasNext()) {
            HeaderItem item = iterator.next();
            if (item.getId() == id) {
                iterator.remove();
                return true;
            }
        }
        return false;
    }

    synchronized public static boolean deleteHeaderItemByIndex(int index) {
        if (index < 0 || index >= headerItemList.size()) {
            return false; // 或者抛出异常
        }
        HeaderItem item = headerItemList.remove(index);
        return item != null;
    }

    synchronized public static HeaderItem deleteHeaderItemByIndexReturnItem(int index) {
        if (index < 0 || index >= headerItemList.size()) {
            return null; // 或者抛出异常
        }
        return headerItemList.remove(index);
    }

    synchronized public static boolean updateHeaderItem(HeaderItem oldHeaderItem, HeaderItem newHeaderItem) {
        if (oldHeaderItem == null || newHeaderItem == null) {
            return false;
        }

        for (int i = 0; i < headerItemList.size(); i++) {
            HeaderItem item = headerItemList.get(i);
            if (item.getId() == oldHeaderItem.getId()) {
                headerItemList.set(i, newHeaderItem);
                return true;
            }
        }
        return false;
    }

    synchronized public static HeaderItem getHeaderItemById(int id) {
        if (id < 0 || id >= headerItemList.size()){
            return null;
        }
        for (HeaderItem headerItem : headerItemList) {
            if (headerItem.getId() == id) {
                return headerItem;
            }
        }
        return null;
    }

    synchronized public static HeaderItem getHeaderItemByIndex(int index) {
        if (index < 0 || index >= headerItemList.size()){
            return null;
        }
        return headerItemList.get(index);
    }

    synchronized public static HeaderItem getHeaderItemByKey(String key) {
        if (key == null || key.isEmpty() || key.trim().isEmpty()){
            return null;
        }
        for (HeaderItem headerItem : headerItemList) {
            if (headerItem.getKey().equals(key)) {
                return headerItem;
            }
        }
        return null;
    }

    synchronized public static List<HeaderItem> getHeaderItemList() {
        return headerItemList;
    }

    synchronized public static void clear() {
        headerItemList.clear();
    }

    synchronized public static boolean deleteHeaderItemByKey(String key) {
        if (key == null || key.isEmpty() || key.trim().isEmpty()){
            return false;
        }
        HeaderItem headerItem = getHeaderItemByKey(key);
        if (headerItem == null){
            return false;
        }
        return headerItemList.remove(headerItem);
    }
}

