package top.oxff.control;

import burp.*;
import top.oxff.model.HeaderItem;
import top.oxff.model.Option;
import top.oxff.util.BytesTools;

import javax.swing.*;
import java.util.*;

import static burp.BurpExtender.TOOL_FLAG_POPUP_MENU;
import static burp.BurpExtender.tableModel;

public class ContextMenuFactoryIml implements IContextMenuFactory {
    Set<Byte> contextSet;

    public ContextMenuFactoryIml() {
        contextSet = new HashSet<>();
        contextSet.add(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST);
        contextSet.add(IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST);
    }

    private enum PopupMenuOption {
        AUTO_REPLACE,
        MANUAL_TRIGGER_REPLACE
    }

    private JMenuItem genMenuItem(String[] selectLines, PopupMenuOption  popupMenuOption) {
        JMenuItem menuItem = new JMenuItem();

        String caption = "新增自动替换头";
        if (popupMenuOption == PopupMenuOption.MANUAL_TRIGGER_REPLACE){
            caption = "新增手动触发替换头";
        }
        Set<Option> optionSet = new HashSet<>();
//        optionSet.add(Option.ADD);
        for (String selectLine : selectLines) {
            String[] kvs = selectLine.split(":", 2);
            if (1 >= kvs.length) {
                continue;
            }
            String k = kvs[0].trim();
            String v = kvs[1].trim();

            if (k.isEmpty() || v.isEmpty()) {
                continue;
            }

            if (tableModel.isExist(k)) {
                optionSet.add(Option.UPDATE);
            } else {
                if (optionSet.contains(Option.UPDATE)) {
                    optionSet.add(Option.ADD_AND_UPDATE);
                } else {
                    optionSet.add(Option.ADD);
                }
            }
        }
        if (optionSet.contains(Option.ADD_AND_UPDATE)) {
            if (popupMenuOption == PopupMenuOption.AUTO_REPLACE){
                caption = "更新 & 新增 自动替换头";
            }else {
                caption = "更新 & 新增 手动触发替换头";
            }

        } else if (optionSet.contains(Option.UPDATE)) {
           if (popupMenuOption == PopupMenuOption.AUTO_REPLACE){
               caption = "更新 自动替换头";
           }else {
               caption = "更新 手动触发替换头";
           }
        }
        menuItem.setText(caption);

        menuItem.addActionListener(e -> {
            for (String selectLine : selectLines) {
                String[] kvs = selectLine.split(":", 2);
                if (1 >= kvs.length) {
                    continue;
                }
                String k = kvs[0].trim();
                String v = kvs[1].trim();

                if (k.isEmpty() || v.isEmpty()) {
                    continue;
                }
                
                // 检查是否存在，如果存在则更新，否则新增
                if (tableModel.isExist(k)) {
                    // 更新现有条目
                    HeaderItem existingItem = tableModel.getHeaderItemByKey(k);
                    existingItem.setValue(v);
                    // 保持其他设置不变
                    tableModel.updateRow(tableModel.getKeyMap().get(k), existingItem);
                } else {
                    // 新增条目
                    HeaderItem headerItem = getHeaderItem(k, v, popupMenuOption);
                    tableModel.addRow(headerItem);
                }
            }
        });
        return menuItem;
    }

    private static HeaderItem getHeaderItem(String k, String v, PopupMenuOption popupMenuOption) {
        HeaderItem headerItem = new HeaderItem();
        headerItem.setKey(k);
        headerItem.setValue(v);
        if (popupMenuOption == PopupMenuOption.MANUAL_TRIGGER_REPLACE){
            headerItem.setProxyEnable(false);
            headerItem.setRepeaterEnable(false);
            headerItem.setIntruderEnable(false);
            headerItem.setScannerEnable(false);
            headerItem.setExtenderEnable(false);
            headerItem.setPopupMenuEnable(true);
            headerItem.setDescription("");
        }else {
            headerItem.setProxyEnable(true);
            headerItem.setRepeaterEnable(true);
            headerItem.setIntruderEnable(true);
            headerItem.setScannerEnable(true);
            headerItem.setExtenderEnable(true);
            headerItem.setPopupMenuEnable(false);
            headerItem.setDescription("");
        }

        return headerItem;

    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation contextMenuInvocation) {
        List<JMenuItem> menuItems = new ArrayList<>();

        IHttpRequestResponse[] selectedMessages = contextMenuInvocation.getSelectedMessages();

        if (!contextSet.contains(contextMenuInvocation.getInvocationContext()) || 0 == selectedMessages.length ) {
            return menuItems;
        }

        int[] selection = contextMenuInvocation.getSelectionBounds();
        if ((null == selection) || (0 == selection.length) || (2 == selection.length && selection[0] == selection[1])){

            if (contextMenuInvocation.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST){
                return menuItems;
            }
            // if header item in table had item that can be popup menu to replace current http editor of headers then  show popup menu
            List<HeaderItem> headerItemList =tableModel.getHeaderItemList();
            List<Integer> needReplaceIndexList = new ArrayList<>();
            for (int i = 0; i < headerItemList.size(); i++) {
                HeaderItem headerItem = headerItemList.get(i);
                if (headerItem.isEnableTool(TOOL_FLAG_POPUP_MENU)) {
                    needReplaceIndexList.add(i);
                }
            }

            if (!needReplaceIndexList.isEmpty()){
                JMenuItem replaceMenuItem = needReplaceMenuItemGen(selectedMessages, needReplaceIndexList, headerItemList);
                menuItems.add(replaceMenuItem);
            }

            return menuItems;

        }

        IHttpRequestResponse httpRequestResponse = selectedMessages[0];
        if (null == httpRequestResponse) {
            return menuItems;
        }

        byte[] data = httpRequestResponse.getRequest();
        if (1 >= data.length) {
            return menuItems;
        }

        String selectStr = new String(Arrays.copyOfRange(data, selection[0], selection[1]));

        String[] selectLines;
        if (selectStr.contains("\r\n")) {
            selectLines = selectStr.split("\r\n");
        } else if (selectStr.contains("\n")) {
            selectLines = selectStr.split("\n");
        } else {
            selectLines = new String[]{selectStr};
        }

        if (0 == selectLines.length) {
            return menuItems;
        }

        JMenuItem autoReplaceMenuItem = genMenuItem(selectLines, PopupMenuOption.AUTO_REPLACE);
        JMenuItem manualReplaceMenuItem = genMenuItem(selectLines, PopupMenuOption.MANUAL_TRIGGER_REPLACE);


        menuItems.add(autoReplaceMenuItem);
        menuItems.add(manualReplaceMenuItem);

        return menuItems;
    }

    private static JMenuItem needReplaceMenuItemGen(IHttpRequestResponse[] selectedMessages, List<Integer> needReplaceIndexList, List<HeaderItem> headerItemList) {
        JMenuItem replaceMenuItem = new JMenuItem("替换");
        replaceMenuItem.addActionListener(e -> {
            // replace the current http editor headers

            byte[] requestBytes = selectedMessages[0].getRequest();
            if (null == requestBytes || 0 == requestBytes.length){
                return;
            }
            IHttpRequestResponse httpRequestResponse = selectedMessages[0];
            IRequestInfo requestInfo = BurpExtender.extensionHelpers.analyzeRequest(httpRequestResponse);
            if (null == requestInfo) {
                return;
            }
            List<String> headers = requestInfo.getHeaders();
            if (headers.isEmpty()) {
                return;
            }
            List<String> tmpHeaders = replaceHeaderItems(headers, needReplaceIndexList, headerItemList);
            int offSet = requestInfo.getBodyOffset();
            byte[] bodyBytes = BytesTools.subByteArray(requestBytes, offSet, requestBytes.length - offSet);
            byte[] finalData = BurpExtender.extensionHelpers.buildHttpMessage(tmpHeaders, bodyBytes);
            httpRequestResponse.setRequest(finalData);
        });
        return replaceMenuItem;
    }

    private static List<String> replaceHeaderItems(List<String> headers, List<Integer> needReplaceIndexList, List<HeaderItem> headerItemList) {
        List<String> tmpHeaders = new ArrayList<>(headers);
        for (Integer needIndex : needReplaceIndexList) {
            HeaderItem headerItem = headerItemList.get(needIndex);
            for (int i = 0; i < tmpHeaders.size(); i++) {
                String header = tmpHeaders.get(i);
                if (!header.contains(":")) {
                    continue;
                }
                String[] header_arr = header.split(":", 2);
                if (2 != header_arr.length) {
                    continue;
                }
                if (header_arr[0].trim().equalsIgnoreCase(headerItem.getKey())) {
                    tmpHeaders.remove(i);
                    tmpHeaders.add(i, String.format("%s: %s", headerItem.getKey(), headerItem.getValue()));
                    break;
                }
            }
        }
        return tmpHeaders;
    }
}