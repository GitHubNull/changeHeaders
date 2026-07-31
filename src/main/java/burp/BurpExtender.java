package burp;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.TypeDescription;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;
import top.oxff.control.ContextMenuFactoryIml;
import top.oxff.control.HttpProcess;
import top.oxff.model.ExtenderConfig;
import top.oxff.model.HeaderItem;
import top.oxff.model.HeaderItemTableModel;
import top.oxff.model.ResponseHeaderConfig;
import top.oxff.service.PreferenceService;
import top.oxff.service.ResponseHeaderService;
import top.oxff.ui.TabUI;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.*;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {
    final static String VERSION = loadVersion();
    final static String NAME = "changeHeaders_v" + VERSION;

    public static IBurpExtenderCallbacks burpExtenderCallbacks;

    public static IExtensionHelpers extensionHelpers;

    public static PrintWriter stdout;
    public static PrintWriter stderr;

    public static final int TOOL_FLAG_POPUP_MENU = 666666;

    public final static Set<Integer> TOOL_FLAGS = new HashSet<>();

    private final static String ExtenderConfig_NAME = "changeHeadersExtenderConfig";

    static TabUI tabUI;
    public static HeaderItemTableModel tableModel;


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks burpExtenderCallbacks) {
        BurpExtender.burpExtenderCallbacks = burpExtenderCallbacks;

        burpExtenderCallbacks.setExtensionName(NAME);

        extensionHelpers = burpExtenderCallbacks.getHelpers();

        stdout = new PrintWriter(BurpExtender.burpExtenderCallbacks.getStdout(), true);
        stderr = new PrintWriter(BurpExtender.burpExtenderCallbacks.getStderr(), true);

        tableModel = new HeaderItemTableModel();

        // 在创建UI之前初始化偏好数据库，确保UI面板能正确加载数据
        initPreferenceDatabase();

        tabUI = new TabUI();

        ContextMenuFactoryIml contextMenuFactoryIml = new ContextMenuFactoryIml();

        BurpExtender.burpExtenderCallbacks.addSuiteTab(this);
        BurpExtender.burpExtenderCallbacks.registerHttpListener(new HttpProcess(extensionHelpers, stdout, stderr));
        BurpExtender.burpExtenderCallbacks.registerContextMenuFactory(contextMenuFactoryIml);
        BurpExtender.burpExtenderCallbacks.registerExtensionStateListener(this);

        SwingUtilities.invokeLater(this::loadExConfig);

        // 输出作者版本等信息
        logInfo("Author: " + "oxff01");
        logInfo("Version: " + VERSION);
        logInfo("Github: " + "https://github.com/oxff01/changeHeaders");
    }



    private void saveExConfig() {
        ExtenderConfig extenderConfig = tabUI.getExtenderConfig();
        
        // 过滤掉非持久化的HeaderItem
        List<HeaderItem> allItems = extenderConfig.getHeaderItemList();
        if (allItems != null) {
            List<HeaderItem> persistentItems = new ArrayList<>();
            for (HeaderItem item : allItems) {
                if (item.isPersistent()) {
                    persistentItems.add(item);
                }
            }
            extenderConfig.setHeaderItemList(persistentItems);
        }
        
        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);

        Representer representer = new Representer(options);
        representer.addClassTag(ExtenderConfig.class, Tag.MAP);
        representer.addClassTag(HeaderItem.class, Tag.MAP);
        representer.addClassTag(ResponseHeaderConfig.class, Tag.MAP);

        Yaml yaml = new Yaml(representer);
        String yamlString = yaml.dump(extenderConfig);
        burpExtenderCallbacks.saveExtensionSetting(ExtenderConfig_NAME, yamlString);
    }


    private void loadExConfig() {
        String yamlString = burpExtenderCallbacks.loadExtensionSetting(ExtenderConfig_NAME);
        if (null == yamlString || yamlString.isEmpty() || yamlString.trim().isEmpty()){
            return;
        }
        try {
            LoaderOptions loaderOptions = new LoaderOptions();
            Constructor constructor = new Constructor(ExtenderConfig.class, loaderOptions);

            TypeDescription configDesc = new TypeDescription(ExtenderConfig.class);
            configDesc.addPropertyParameters("headerItemList", HeaderItem.class);
            constructor.addTypeDescription(configDesc);

            TypeDescription respDesc = new TypeDescription(ResponseHeaderConfig.class);
            respDesc.addPropertyParameters("responseToolFlags", Integer.class);
            constructor.addTypeDescription(respDesc);

            Yaml yaml = new Yaml(constructor);
            ExtenderConfig config = yaml.load(yamlString);

            tabUI.setCheckBoxStatus(config);
            if (null != config.getKeyMap() && !config.getKeyMap().isEmpty()) {
                tableModel.setKeyMap(config.getKeyMap());
            }
            if (null != config.getHeaderItemList() && !config.getHeaderItemList().isEmpty()) {
                tableModel.setHeaderItemList(config.getHeaderItemList());
            }
            if(null != config.getToolFlags() && !config.getToolFlags().isEmpty()){
                TOOL_FLAGS.addAll(config.getToolFlags());
            }
            // 旧版本配置无响应头节点时保持默认关闭状态
            if (null != config.getResponseHeaderConfig()) {
                ResponseHeaderService.loadConfig(config.getResponseHeaderConfig());
                tabUI.loadResponseHeaderConfig(ResponseHeaderService.buildConfig());
            }
        }catch (Exception e){
            stdout.println("parse yaml object error: " + e.getMessage());
        }
    }


    @Override
    public void extensionUnloaded() {
        PreferenceService.shutdown();
        saveExConfig();
    }

    @Override
    public String getTabCaption() {
        return NAME;
    }

    @Override
    public Component getUiComponent() {
        return tabUI;
    }

    public static void logInfo(String info) {
        stdout.println(info);
    }

    public static void logError(String error) {
        stderr.println(error);
    }

    /**
     * 从 version.properties 加载版本号（构建时由 Maven 资源过滤注入）
     */
    private static String loadVersion() {
        try (InputStream is = BurpExtender.class.getResourceAsStream("/version.properties")) {
            if (is != null) {
                Properties props = new Properties();
                props.load(is);
                return props.getProperty("version", "unknown");
            }
        } catch (Exception ignored) {
        }
        return "unknown";
    }

    /**
     * 初始化偏好数据库
     */
    private void initPreferenceDatabase() {
        try {
            String dbPath = resolveDbPath();
            PreferenceService.initDatabase(dbPath);
        } catch (Exception e) {
            logError("Failed to initialize preference database: " + e.getMessage());
        }
    }

    /**
     * 解析偏好数据库文件路径
     * 优先从Burp扩展设置中读取，若为空则使用默认路径并保存设置
     */
    private String resolveDbPath() {
        String savedPath = burpExtenderCallbacks.loadExtensionSetting("changeHeadersDbPath");
        if (savedPath != null && !savedPath.trim().isEmpty()) {
            return savedPath;
        }

        // 默认路径：用户主目录下的.BurpSuite目录
        String userHome = System.getProperty("user.home");
        File burpDir = new File(userHome, ".BurpSuite");
        if (!burpDir.exists()) {
            burpDir.mkdirs();
        }
        String dbPath = new File(burpDir, "changeHeaders_prefs.db").getAbsolutePath();
        burpExtenderCallbacks.saveExtensionSetting("changeHeadersDbPath", dbPath);
        return dbPath;
    }

}