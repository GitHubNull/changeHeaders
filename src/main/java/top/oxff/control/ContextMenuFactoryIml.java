package top.oxff.control;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import top.oxff.model.HeaderItem;
import top.oxff.model.Option;

import javax.swing.*;
import java.util.*;

import static burp.BurpExtender.tableModel;

public class ContextMenuFactoryIml implements IContextMenuFactory {
    Set<Byte> contextSet;

    public ContextMenuFactoryIml() {
        contextSet = new HashSet<>();
        contextSet.add(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST);
        contextSet.add(IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST);
    }

    private JMenuItem genMenuItem(String[] selectLines) {
        JMenuItem menuItem = new JMenuItem(); // "[changeHeaders] 新增"

        String title = "[changeHeaders] 新增";
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
            title = "[changeHeaders] 新增 & 更新";
        } else if (optionSet.contains(Option.UPDATE)) {
            title = "[changeHeaders] 更新";
        }
        menuItem.setText(title);

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
                HeaderItem headerItem = new HeaderItem();
                headerItem.setKey(k);
                headerItem.setValue(v);
                headerItem.setProxyEnable(false);
                headerItem.setRepeaterEnable(true);
                headerItem.setIntruderEnable(true);
                headerItem.setScannerEnable(true);
                headerItem.setExtenderEnable(true);
                headerItem.setDescription("");
                tableModel.addRow(headerItem);
            }
        });
        return menuItem;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation contextMenuInvocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        int[] selection = contextMenuInvocation.getSelectionBounds();
        IHttpRequestResponse[] selectedMessages = contextMenuInvocation.getSelectedMessages();


        if (!contextSet.contains(contextMenuInvocation.getInvocationContext()) ||
                (null == selectedMessages || null == selection) || (1 >= selection.length) ||
                0 == selectedMessages.length) {
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


        JMenuItem menuItem = genMenuItem(selectLines);

        menuItems.add(menuItem);


        return menuItems;
    }
}
