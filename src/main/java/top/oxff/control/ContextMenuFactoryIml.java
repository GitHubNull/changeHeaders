package top.oxff.control;

import burp.BurpExtender;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;

public class ContextMenuFactoryIml implements IContextMenuFactory {
    Set<Byte> contextSet;
    static String[] selectLines = null;

    public ContextMenuFactoryIml() {
        contextSet = new HashSet<>();

        contextSet.add(IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST);
        contextSet.add(IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST);

    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation contextMenuInvocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        int[] selection = contextMenuInvocation.getSelectionBounds();
        IHttpRequestResponse[] selectedMessages = contextMenuInvocation.getSelectedMessages();


        if (!contextSet.contains(contextMenuInvocation.getInvocationContext()) || (null == selectedMessages || null == selection)|| (1 >= selection.length) || 0 >= selectedMessages.length){
            return menuItems;
        }



        IHttpRequestResponse httpRequestResponse = selectedMessages[0];
        if (null == httpRequestResponse){
            return menuItems;
        }

        byte[] data = httpRequestResponse.getRequest();
        if (1 >= data.length){
            return menuItems;
        }

        String selectStr = new String(Arrays.copyOfRange(data, selection[0], selection[1]));



        if (selectStr.contains("\r\n")){
            selectLines = selectStr.split("\r\n");
        }else if (selectStr.contains("\n")){
            selectLines = selectStr.split("\n");
        }else {
            selectLines = new String[]{selectStr};
        }

        if (null == selectLines || 0 == selectLines.length){
            return menuItems;
        }


        JMenuItem menuItem = new JMenuItem("[changeHeaders] 新增");
        menuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                for (String selectLine : selectLines) {
                    String[] kvs = selectLine.split(":", 2);
                    if (null == kvs || 1 >= kvs.length){
                        continue;
                    }
                    String k = kvs[0].trim();
                    String v = kvs[1].trim();

                    if (k.isEmpty()){
                        continue;
                    }

                    BurpExtender.addKVITem(k, v, "是");

                }
            }
        });

        menuItems.add(menuItem);



        return menuItems;
    }
}
