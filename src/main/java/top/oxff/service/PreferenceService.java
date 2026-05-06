package top.oxff.service;

import burp.BurpExtender;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;
import top.oxff.model.PreferenceConfig;

import java.sql.*;
import java.util.*;

/**
 * 偏好数据持久化服务
 * 使用SQLite存储用户持久化的请求头键名和内置匹配关键词
 */
public class PreferenceService {

    private static Connection connection;
    private static volatile boolean initialized = false;

    private static final String[] DEFAULT_KEYWORDS = {"cookie", "token", "authorization", "auth", "jwt", "session"};

    /**
     * 初始化数据库连接和表结构
     */
    synchronized public static void initDatabase(String dbPath) {
        try {
            Class.forName("org.sqlite.JDBC");
            connection = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
            connection.setAutoCommit(true);

            // 开启WAL模式
            try (Statement stmt = connection.createStatement()) {
                stmt.execute("PRAGMA journal_mode=WAL");
            }

            createTables();
            seedDefaultKeywords();
            initialized = true;
            BurpExtender.logInfo("Preference database initialized: " + dbPath);
        } catch (Exception e) {
            BurpExtender.logError("Failed to initialize preference database: " + e.getMessage());
            initialized = false;
        }
    }

    /**
     * 关闭数据库连接
     */
    synchronized public static void shutdown() {
        if (connection != null) {
            try {
                connection.close();
                BurpExtender.logInfo("Preference database connection closed");
            } catch (SQLException e) {
                BurpExtender.logError("Failed to close preference database: " + e.getMessage());
            }
            connection = null;
            initialized = false;
        }
    }

    public static boolean isInitialized() {
        return initialized;
    }

    private static void createTables() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS persisted_header_keys (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "header_key TEXT NOT NULL UNIQUE, " +
                    "created_at INTEGER NOT NULL DEFAULT 0)");

            stmt.execute("CREATE TABLE IF NOT EXISTS builtin_keywords (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "keyword TEXT NOT NULL UNIQUE, " +
                    "created_at INTEGER NOT NULL DEFAULT 0)");

            stmt.execute("CREATE TABLE IF NOT EXISTS preference_meta (" +
                    "key TEXT PRIMARY KEY, " +
                    "value TEXT NOT NULL)");
        }
    }

    private static void seedDefaultKeywords() throws SQLException {
        // 检查是否已有数据
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM builtin_keywords")) {
            if (rs.next() && rs.getInt(1) > 0) {
                return; // 已有数据，不覆盖
            }
        }

        long now = System.currentTimeMillis();
        try (PreparedStatement pstmt = connection.prepareStatement(
                "INSERT OR IGNORE INTO builtin_keywords (keyword, created_at) VALUES (?, ?)")) {
            for (String keyword : DEFAULT_KEYWORDS) {
                pstmt.setString(1, keyword);
                pstmt.setLong(2, now);
                pstmt.executeUpdate();
            }
        }
    }

    // ==================== Persisted Header Keys ====================

    synchronized public static List<String> getPersistedHeaderKeys() {
        List<String> keys = new ArrayList<>();
        if (!initialized) return keys;

        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT header_key FROM persisted_header_keys ORDER BY id")) {
            while (rs.next()) {
                keys.add(rs.getString("header_key"));
            }
        } catch (SQLException e) {
            BurpExtender.logError("Failed to get persisted header keys: " + e.getMessage());
        }
        return keys;
    }

    synchronized public static boolean addPersistedHeaderKey(String key) {
        if (!initialized || key == null || key.trim().isEmpty()) return false;

        try (PreparedStatement pstmt = connection.prepareStatement(
                "INSERT OR IGNORE INTO persisted_header_keys (header_key, created_at) VALUES (?, ?)")) {
            pstmt.setString(1, key.trim());
            pstmt.setLong(2, System.currentTimeMillis());
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.logError("Failed to add persisted header key: " + e.getMessage());
            return false;
        }
    }

    synchronized public static boolean removePersistedHeaderKey(String key) {
        if (!initialized || key == null || key.trim().isEmpty()) return false;

        try (PreparedStatement pstmt = connection.prepareStatement(
                "DELETE FROM persisted_header_keys WHERE header_key = ?")) {
            pstmt.setString(1, key.trim());
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.logError("Failed to remove persisted header key: " + e.getMessage());
            return false;
        }
    }

    synchronized public static boolean clearPersistedHeaderKeys() {
        if (!initialized) return false;

        try (Statement stmt = connection.createStatement()) {
            stmt.execute("DELETE FROM persisted_header_keys");
            return true;
        } catch (SQLException e) {
            BurpExtender.logError("Failed to clear persisted header keys: " + e.getMessage());
            return false;
        }
    }

    // ==================== Builtin Keywords ====================

    synchronized public static List<String> getBuiltinKeywords() {
        List<String> keywords = new ArrayList<>();
        if (!initialized) return keywords;

        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT keyword FROM builtin_keywords ORDER BY id")) {
            while (rs.next()) {
                keywords.add(rs.getString("keyword"));
            }
        } catch (SQLException e) {
            BurpExtender.logError("Failed to get builtin keywords: " + e.getMessage());
        }
        return keywords;
    }

    synchronized public static boolean addBuiltinKeyword(String keyword) {
        if (!initialized || keyword == null || keyword.trim().isEmpty()) return false;

        try (PreparedStatement pstmt = connection.prepareStatement(
                "INSERT OR IGNORE INTO builtin_keywords (keyword, created_at) VALUES (?, ?)")) {
            pstmt.setString(1, keyword.trim().toLowerCase());
            pstmt.setLong(2, System.currentTimeMillis());
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.logError("Failed to add builtin keyword: " + e.getMessage());
            return false;
        }
    }

    synchronized public static boolean removeBuiltinKeyword(String keyword) {
        if (!initialized || keyword == null || keyword.trim().isEmpty()) return false;

        try (PreparedStatement pstmt = connection.prepareStatement(
                "DELETE FROM builtin_keywords WHERE keyword = ?")) {
            pstmt.setString(1, keyword.trim().toLowerCase());
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.logError("Failed to remove builtin keyword: " + e.getMessage());
            return false;
        }
    }

    synchronized public static boolean updateBuiltinKeyword(String oldKeyword, String newKeyword) {
        if (!initialized || oldKeyword == null || newKeyword == null || newKeyword.trim().isEmpty()) return false;

        try (PreparedStatement pstmt = connection.prepareStatement(
                "UPDATE builtin_keywords SET keyword = ? WHERE keyword = ?")) {
            pstmt.setString(1, newKeyword.trim().toLowerCase());
            pstmt.setString(2, oldKeyword.trim().toLowerCase());
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            BurpExtender.logError("Failed to update builtin keyword: " + e.getMessage());
            return false;
        }
    }

    synchronized public static boolean resetBuiltinKeywordsToDefaults() {
        if (!initialized) return false;

        try (Statement stmt = connection.createStatement()) {
            stmt.execute("DELETE FROM builtin_keywords");
        } catch (SQLException e) {
            BurpExtender.logError("Failed to clear builtin keywords for reset: " + e.getMessage());
            return false;
        }

        try (PreparedStatement pstmt = connection.prepareStatement(
                "INSERT OR IGNORE INTO builtin_keywords (keyword, created_at) VALUES (?, ?)")) {
            long now = System.currentTimeMillis();
            for (String keyword : DEFAULT_KEYWORDS) {
                pstmt.setString(1, keyword);
                pstmt.setLong(2, now);
                pstmt.executeUpdate();
            }
            return true;
        } catch (SQLException e) {
            BurpExtender.logError("Failed to seed default keywords: " + e.getMessage());
            return false;
        }
    }

    // ==================== Import / Export ====================

    /**
     * 导出偏好数据为YAML字符串
     */
    synchronized public static String exportPreferences() {
        PreferenceConfig config = new PreferenceConfig();
        config.setPersistedHeaderKeys(getPersistedHeaderKeys());
        config.setBuiltinKeywords(getBuiltinKeywords());
        config.setExportedAt(System.currentTimeMillis());

        DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);
        Yaml yaml = new Yaml(options);
        return yaml.dump(config);
    }

    /**
     * 从YAML字符串导入偏好数据，替换所有现有数据
     */
    synchronized public static boolean importPreferences(String yamlContent) {
        if (!initialized || yamlContent == null || yamlContent.trim().isEmpty()) return false;

        try {
            Yaml yaml = new Yaml();
            Map<String, Object> data = yaml.load(yamlContent);

            if (data == null) return false;

            List<String> persistedKeys = null;
            List<String> keywords = null;

            Object persistedObj = data.get("persistedHeaderKeys");
            if (persistedObj instanceof List) {
                persistedKeys = new ArrayList<>();
                for (Object item : (List<?>) persistedObj) {
                    if (item != null) {
                        persistedKeys.add(item.toString());
                    }
                }
            }

            Object keywordsObj = data.get("builtinKeywords");
            if (keywordsObj instanceof List) {
                keywords = new ArrayList<>();
                for (Object item : (List<?>) keywordsObj) {
                    if (item != null) {
                        keywords.add(item.toString());
                    }
                }
            }

            // 替换持久化键名
            if (persistedKeys != null) {
                try (Statement stmt = connection.createStatement()) {
                    stmt.execute("DELETE FROM persisted_header_keys");
                }
                try (PreparedStatement pstmt = connection.prepareStatement(
                        "INSERT OR IGNORE INTO persisted_header_keys (header_key, created_at) VALUES (?, ?)")) {
                    long now = System.currentTimeMillis();
                    for (String key : persistedKeys) {
                        pstmt.setString(1, key.trim());
                        pstmt.setLong(2, now);
                        pstmt.executeUpdate();
                    }
                }
            }

            // 替换关键词
            if (keywords != null) {
                try (Statement stmt = connection.createStatement()) {
                    stmt.execute("DELETE FROM builtin_keywords");
                }
                try (PreparedStatement pstmt = connection.prepareStatement(
                        "INSERT OR IGNORE INTO builtin_keywords (keyword, created_at) VALUES (?, ?)")) {
                    long now = System.currentTimeMillis();
                    for (String keyword : keywords) {
                        pstmt.setString(1, keyword.trim().toLowerCase());
                        pstmt.setLong(2, now);
                        pstmt.executeUpdate();
                    }
                }
            }

            return true;
        } catch (Exception e) {
            BurpExtender.logError("Failed to import preferences: " + e.getMessage());
            return false;
        }
    }
}
