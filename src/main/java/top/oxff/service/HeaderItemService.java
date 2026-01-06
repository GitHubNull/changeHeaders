package top.oxff.service;

import burp.BurpExtender;
import top.oxff.model.HeaderItem;

import java.util.*;

public class HeaderItemService {
//    private static HeaderItemService instance;
    private static final List<HeaderItem> headerItemList = new ArrayList<>();
    private static final Map<String, Integer> keyMap = new HashMap<>();

    synchronized public static int addHeaderItem(HeaderItem headerItem) {
        if (keyMap.containsKey(headerItem.getKey())) {
            int id = keyMap.get(headerItem.getKey());
            headerItem.setId(id);
            headerItemList.set(id, headerItem);
            return id;
        }
        headerItem.setId(headerItemList.size());
        keyMap.put(headerItem.getKey(), headerItem.getId());
        headerItemList.add(headerItem);
        return headerItem.getId();
    }

    synchronized public static boolean deleteHeaderItemById(int id) {
        if (id < 0 || id >= headerItemList.size()) {
            return false; // 或者抛出异常
        }
        Iterator<HeaderItem> iterator = headerItemList.iterator();
        boolean removed = false;
        while (iterator.hasNext()) {
            HeaderItem item = iterator.next();
            if (item.getId() == id) {
                iterator.remove();
                removed = true;
                break;
            }
        }
        
        if (removed) {
            // 重新构建keyMap，因为删除后索引发生变化
            keyMap.clear();
            for (int i = 0; i < headerItemList.size(); i++) {
                HeaderItem currentItem = headerItemList.get(i);
                currentItem.setId(i); // 更新ID
                keyMap.put(currentItem.getKey(), i);
            }
        }
        
        return removed;
    }

    synchronized public static boolean deleteHeaderItemByIndex(int index) {
        if (index < 0 || index >= headerItemList.size()) {
            return false; // 或者抛出异常
        }
        HeaderItem item = headerItemList.remove(index);
        
        // 重新构建keyMap，因为删除后索引发生变化
        keyMap.clear();
        for (int i = 0; i < headerItemList.size(); i++) {
            HeaderItem currentItem = headerItemList.get(i);
            currentItem.setId(i); // 更新ID
            keyMap.put(currentItem.getKey(), i);
        }
        
        return true;
    }

    synchronized public static boolean deleteHeaderItemByIndexReturnItem(int index) {
        if (index < 0 || index >= headerItemList.size()) {
            return false;
        }
        HeaderItem item = headerItemList.remove(index);
        keyMap.remove(item.getKey());
        return true;
    }

    synchronized public static boolean updateHeaderItem(HeaderItem oldHeaderItem, HeaderItem newHeaderItem) {
        if (oldHeaderItem == null || newHeaderItem == null) {
            return false;
        }
        int id = oldHeaderItem.getId();
        try {
            headerItemList.set(id, newHeaderItem);
            keyMap.remove(oldHeaderItem.getKey());
            keyMap.put(newHeaderItem.getKey(), newHeaderItem.getId());
            return true;
        }catch (Exception e){
            BurpExtender.stderr.println("updateHeaderItem error: " + e.getMessage());
            return false;
        }

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
        if (key == null || key.isEmpty() || key.trim().isEmpty() || !keyMap.containsKey(key)){
            return null;
        }
        Integer index = keyMap.get(key);
        // 增加索引边界检查，防止IndexOutOfBoundsException
        if (index == null || index < 0 || index >= headerItemList.size()) {
            return null;
        }
        return headerItemList.get(index);
    }

    synchronized public static List<HeaderItem> getHeaderItemList() {
        return headerItemList;
    }

    synchronized public static int getHeaderItemListSize() {
        return headerItemList.size();
    }

    synchronized public static void clear() {
        headerItemList.clear();
        keyMap.clear();
    }

    synchronized public static boolean deleteHeaderItemByKey(String key) {
        if (key == null || key.isEmpty() || key.trim().isEmpty()){
            return false;
        }
        HeaderItem headerItem = getHeaderItemByKey(key);
        if (headerItem == null){
            return false;
        }
        boolean removed = headerItemList.remove(headerItem);
        
        if (removed) {
            // 重新构建keyMap，因为删除后索引发生变化
            keyMap.clear();
            for (int i = 0; i < headerItemList.size(); i++) {
                HeaderItem currentItem = headerItemList.get(i);
                currentItem.setId(i); // 更新ID
                keyMap.put(currentItem.getKey(), i);
            }
        }
        
        return removed;
    }

    synchronized public static Map<String, Integer> getKeyMap(){
        return keyMap;
    }

    synchronized public static void setHeaderItemList(List<HeaderItem> headerItemList) {
        HeaderItemService.headerItemList.clear();
        HeaderItemService.headerItemList.addAll(headerItemList);
        
        // 更新每个HeaderItem的ID以匹配其在列表中的索引
        for (int i = 0; i < HeaderItemService.headerItemList.size(); i++) {
            HeaderItemService.headerItemList.get(i).setId(i);
        }
        
        // 重新构建keyMap
        keyMap.clear();
        for (int i = 0; i < HeaderItemService.headerItemList.size(); i++) {
            HeaderItem item = HeaderItemService.headerItemList.get(i);
            keyMap.put(item.getKey(), i);
        }
    }

    synchronized public static void setKeyMap(Map<String, Integer> keyMap) {
        HeaderItemService.keyMap.clear();
        HeaderItemService.keyMap.putAll(keyMap);
    }

    synchronized public static boolean isExist(String key) {
        if (key == null || key.isEmpty() || key.trim().isEmpty()){
            return false;
        }
        return keyMap.containsKey(key);
    }
}