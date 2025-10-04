package s.zSanchez;

import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.lang.reflect.Method;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.logging.*;

@SuppressWarnings("unchecked")
public class Skyfall {

    private static Map<String, Object> config;
    private static volatile boolean running = true;
    private static ExecutorService clientThreads;
    private static final Map<String, Integer> onlinePlayers = new ConcurrentHashMap<>();
    private static final Map<String, String> playerServers = new ConcurrentHashMap<>();
    private static final Map<String, String> playerIPs = new ConcurrentHashMap<>();
    private static final List<SkyfallPlugin> loadedPlugins = new ArrayList<>();
    private static final Map<String, Long> connectionThrottle = new ConcurrentHashMap<>();
    private static final Set<String> bannedIPs = ConcurrentHashMap.newKeySet();
    private static boolean guiMode = true;
    private static ServerSocket serverSocket;
    private static final SkyfallAPI skyfallAPI = new SkyfallAPI();
    private static final String VERSION = "git:Skyfall-Bootstrap:1.20-R0.1:skyfall:001";
    private static final Logger LOGGER = Logger.getLogger("Skyfall");

    public static void main(String[] args) {
        setupLogger();

        if (args.length > 0 && args[0].equalsIgnoreCase("nogui")) {
            guiMode = false;
        }

        LOGGER.info("*** Hey! This build is potentially outdated :( ***");
        LOGGER.info("*** Please check for a new build from https://github.com/yourname/skyfall ***");
        LOGGER.info("*** Should this build be outdated, you will get NO support for it. ***");

        File configFile = getConfigFile();

        if (!configFile.exists()) {
            try {
                createDefaultConfig(configFile);
                LOGGER.info("Generated default config.yml");
            } catch (IOException e) {
                LOGGER.severe("Error creating config.yml: " + e.getMessage());
                return;
            }
        }

        if (!loadConfig(configFile)) {
            LOGGER.severe("Failed to load config.yml");
            return;
        }

        clientThreads = Executors.newCachedThreadPool();
        LOGGER.info("Using cached thread pool");

        Map<String, Map<String, Object>> servers = (Map<String, Map<String, Object>>) config.get("servers");
        if (servers != null) {
            servers.keySet().forEach(server -> onlinePlayers.put(server, 0));
        }

        LOGGER.info("Using standard Java JCE cipher.");
        LOGGER.info("Using standard Java compressor.");

        loadPlugins();

        LOGGER.info("Enabled Skyfall version " + VERSION);

        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            LOGGER.info("Not on Windows, attempting to use enhanced EpollEventLoop");
            LOGGER.warning("Epoll is not working, falling back to NIO");
        }

        enablePlugins();

        showStartupInfo();
        startNetworkListener();
        startConsole();
    }

    private static void setupLogger() {
        try {
            LogManager.getLogManager().reset();
            LOGGER.setLevel(Level.ALL);

            ConsoleHandler consoleHandler = new ConsoleHandler();
            consoleHandler.setLevel(Level.ALL);
            consoleHandler.setFormatter(new SimpleFormatter() {
                private static final String format = "[%1$tT INFO]: %2$s%n";

                @Override
                public synchronized String format(LogRecord lr) {
                    String message = lr.getMessage();
                    // Convertir códigos de color & a ANSI para macOS/Linux
                    message = convertColorsToANSI(message);
                    return String.format(format,
                            new Date(lr.getMillis()),
                            message
                    );
                }

                private String convertColorsToANSI(String text) {
                    if (text == null) return "";

                    return text.replace("&0", "\u001B[30m")  // Black
                            .replace("&1", "\u001B[34m")  // Dark Blue
                            .replace("&2", "\u001B[32m")  // Dark Green
                            .replace("&3", "\u001B[36m")  // Dark Aqua
                            .replace("&4", "\u001B[31m")  // Dark Red
                            .replace("&5", "\u001B[35m")  // Dark Purple
                            .replace("&6", "\u001B[33m")  // Gold
                            .replace("&7", "\u001B[37m")  // Gray
                            .replace("&8", "\u001B[90m")  // Dark Gray
                            .replace("&9", "\u001B[94m")  // Blue
                            .replace("&a", "\u001B[92m")  // Green
                            .replace("&b", "\u001B[96m")  // Aqua
                            .replace("&c", "\u001B[91m")  // Red
                            .replace("&d", "\u001B[95m")  // Light Purple
                            .replace("&e", "\u001B[93m")  // Yellow
                            .replace("&f", "\u001B[97m")  // White
                            .replace("&l", "\u001B[1m")   // Bold
                            .replace("&n", "\u001B[4m")   // Underline
                            .replace("&r", "\u001B[0m");  // Reset
                }
            });
            LOGGER.addHandler(consoleHandler);

            File logsDir = new File("logs");
            if (!logsDir.exists()) {
                logsDir.mkdirs();
            }

            FileHandler fileHandler = new FileHandler("logs/skyfall.log", 10 * 1024 * 1024, 5, true);
            fileHandler.setLevel(Level.ALL);
            fileHandler.setFormatter(new SimpleFormatter() {
                private static final String format = "[%1$tT INFO]: %2$s%n";

                @Override
                public synchronized String format(LogRecord lr) {
                    // En el archivo de log, quitar los códigos de color
                    String message = lr.getMessage();
                    if (message != null) {
                        message = message.replaceAll("&[0-9a-fk-or]", "");
                    }
                    return String.format(format,
                            new Date(lr.getMillis()),
                            message
                    );
                }
            });
            LOGGER.addHandler(fileHandler);

        } catch (IOException e) {
            System.err.println("Failed to setup logger: " + e.getMessage());
        }
    }

    private static void loadPlugins() {
        File pluginsDir = new File(getJarDirectory(), "plugins");
        if (!pluginsDir.exists()) {
            pluginsDir.mkdirs();
            LOGGER.info("Created plugins directory");
            return;
        }

        File modulesDir = new File(getJarDirectory(), "modules");
        if (!modulesDir.exists()) {
            modulesDir.mkdirs();
        }

        // Cargar módulos primero
        loadModulesFromDirectory(modulesDir);

        // Luego cargar plugins
        File[] jarFiles = pluginsDir.listFiles((dir, name) -> name.endsWith(".jar"));
        if (jarFiles == null || jarFiles.length == 0) {
            LOGGER.info("No plugins found in plugins directory");
            return;
        }

        for (File jarFile : jarFiles) {
            try {
                loadPlugin(jarFile);
            } catch (Exception e) {
                LOGGER.severe("Failed to load plugin " + jarFile.getName() + ": " + e.getMessage());
            }
        }
    }

    private static void loadModulesFromDirectory(File dir) {
        File[] moduleFiles = dir.listFiles((d, name) -> name.endsWith(".jar"));
        if (moduleFiles == null || moduleFiles.length == 0) {
            return;
        }

        for (File moduleFile : moduleFiles) {
            String moduleName = moduleFile.getName().replace(".jar", "");
            LOGGER.info("Discovered module: " + moduleName);
        }
    }

    private static void loadPlugin(File jarFile) throws Exception {
        try (JarFile jar = new JarFile(jarFile)) {
            JarEntry pluginYml = jar.getJarEntry("plugin.yml");
            if (pluginYml == null) {
                LOGGER.info("Discovered module: " + jarFile.getName().replace(".jar", ""));
                return;
            }

            try (InputStream in = jar.getInputStream(pluginYml)) {
                Yaml yaml = new Yaml();
                Map<String, Object> pluginInfo = yaml.load(in);

                String name = (String) pluginInfo.getOrDefault("name", "Unknown");
                String version = (String) pluginInfo.getOrDefault("version", "1.0.0");
                String author = (String) pluginInfo.getOrDefault("author", "Unknown");
                String mainClass = (String) pluginInfo.get("main");

                LOGGER.info("Loaded plugin " + name + " version " + version + " by " + author);

                if (mainClass != null) {
                    URLClassLoader classLoader = new URLClassLoader(
                            new URL[]{jarFile.toURI().toURL()},
                            Skyfall.class.getClassLoader()
                    );
                    Class<?> pluginClass = classLoader.loadClass(mainClass);
                    SkyfallPlugin plugin = (SkyfallPlugin) pluginClass.getDeclaredConstructor().newInstance();

                    try {
                        Method setApiMethod = pluginClass.getMethod("setAPI", SkyfallAPI.class);
                        setApiMethod.invoke(plugin, skyfallAPI);
                    } catch (NoSuchMethodException e) {
                        // Plugin doesn't have setAPI method, ignore
                    }

                    // Set data folder for plugins that need it
                    try {
                        Method setDataFolderMethod = pluginClass.getMethod("setDataFolder", File.class);
                        File pluginDataFolder = new File(getJarDirectory(), "plugins/" + name);
                        if (!pluginDataFolder.exists()) {
                            pluginDataFolder.mkdirs();
                        }
                        setDataFolderMethod.invoke(plugin, pluginDataFolder);
                    } catch (NoSuchMethodException e) {
                        // Plugin doesn't have setDataFolder method, ignore
                    }

                    loadedPlugins.add(plugin);
                }
            }
        }
    }

    private static void enablePlugins() {
        for (SkyfallPlugin plugin : loadedPlugins) {
            try {
                plugin.onEnable();
                LOGGER.info("Enabled plugin " + plugin.getName() + " version " + plugin.getVersion());
            } catch (Exception e) {
                LOGGER.severe("Error enabling plugin " + plugin.getName() + ": " + e.getMessage());
            }
        }
    }

    private static String getJarDirectory() {
        try {
            return new File(Skyfall.class.getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI())
                    .getParent();
        } catch (Exception e) {
            return ".";
        }
    }

    private static File getConfigFile() {
        try {
            String jarDir = getJarDirectory();
            return new File(jarDir, "config.yml");
        } catch (Exception e) {
            return new File("config.yml");
        }
    }

    private static void createDefaultConfig(File configFile) throws IOException {
        String defaultConfig = "# ==========================================\n" +
                "#    Skyfall Proxy Configuration\n" +
                "# ==========================================\n" +
                "listeners:\n" +
                "  - query_port: 25577\n" +
                "    motd: '&6&lSkyfall Proxy\\n&7¡Bienvenido al servidor!'\n" +
                "    tab_list: GLOBAL_PING\n" +
                "    query_enabled: false\n" +
                "    proxy_protocol: false\n" +
                "    ping_passthrough: false\n" +
                "    priorities:\n" +
                "      - lobby\n" +
                "    bind_local_address: true\n" +
                "    host: 0.0.0.0:25577\n" +
                "    max_players: 100\n" +
                "    tab_size: 60\n" +
                "    force_default_server: false\n" +
                "    forced_hosts:\n" +
                "      pvp.example.com: pvp\n" +
                "      lobby.example.com: lobby\n" +
                "servers:\n" +
                "  lobby:\n" +
                "    motd: '&aServidor Lobby'\n" +
                "    address: localhost:25565\n" +
                "    restricted: false\n" +
                "groups:\n" +
                "  admin:\n" +
                "    - bungeecord.command.alert\n" +
                "    - bungeecord.command.end\n" +
                "    - bungeecord.command.ip\n" +
                "    - bungeecord.command.reload\n" +
                "  user:\n" +
                "    - bungeecord.command.server\n" +
                "    - bungeecord.command.list\n" +
                "    - bungeecord.command.send\n" +
                "connection_throttle: 4000\n" +
                "connection_throttle_limit: 3\n" +
                "timeout: 30000\n" +
                "log_commands: false\n" +
                "log_pings: true\n" +
                "online_mode: true\n" +
                "ip_forward: true\n" +
                "network_compression_threshold: 256\n" +
                "player_limit: -1\n" +
                "prevent_proxy_connections: false\n" +
                "disabled_commands:\n" +
                "  - disabledcommandhere\n" +
                "forge_support: false\n" +
                "inject_commands: false\n" +
                "stats: " + UUID.randomUUID().toString();

        try (FileWriter writer = new FileWriter(configFile, StandardCharsets.UTF_8)) {
            writer.write(defaultConfig);
        }
    }

    private static boolean loadConfig(File configFile) {
        try (InputStream in = new FileInputStream(configFile)) {
            Yaml yaml = new Yaml();
            Object loaded = yaml.load(in);
            if (loaded instanceof Map) {
                config = (Map<String, Object>) loaded;
                return true;
            } else {
                LOGGER.severe("Config is not a valid map.");
                return false;
            }
        } catch (IOException e) {
            LOGGER.severe("Error loading config.yml: " + e.getMessage());
            return false;
        }
    }

    private static void showStartupInfo() {
        List<Map<String, Object>> listeners = (List<Map<String, Object>>) config.get("listeners");
        if (listeners != null && !listeners.isEmpty()) {
            Map<String, Object> listener = listeners.get(0);
            String host = (String) listener.getOrDefault("host", "0.0.0.0:25577");
            int maxPlayers = (int) listener.getOrDefault("max_players", 100);
            boolean onlineMode = (boolean) config.getOrDefault("online_mode", true);
            boolean ipForward = (boolean) config.getOrDefault("ip_forward", true);

            Map<String, Map<String, Object>> servers = (Map<String, Map<String, Object>>) config.get("servers");
            int serverCount = servers != null ? servers.size() : 0;

            LOGGER.info("Listening on /" + host);
            LOGGER.info("Online mode: " + (onlineMode ? "enabled" : "disabled"));
            LOGGER.info("IP forwarding: " + (ipForward ? "enabled" : "disabled"));
            LOGGER.info("Max players: " + maxPlayers);
            LOGGER.info("Registered " + serverCount + " backend server(s)");
        }
    }

    private static void startNetworkListener() {
        List<Map<String, Object>> listeners = (List<Map<String, Object>>) config.get("listeners");
        if (listeners == null || listeners.isEmpty()) {
            LOGGER.severe("No listeners configured!");
            return;
        }

        Map<String, Object> listener = listeners.get(0);
        String host = (String) listener.getOrDefault("host", "0.0.0.0:25577");
        String[] parts = host.split(":");
        String bindAddress = parts[0];
        int port = Integer.parseInt(parts[1]);

        new Thread(() -> {
            try {
                serverSocket = new ServerSocket(port);
                serverSocket.setReuseAddress(true);

                while (running) {
                    try {
                        Socket client = serverSocket.accept();

                        String clientIP = client.getInetAddress().getHostAddress();
                        if (!checkConnectionThrottle(clientIP)) {
                            client.close();
                            continue;
                        }

                        if (bannedIPs.contains(clientIP)) {
                            client.close();
                            continue;
                        }

                        int timeout = (int) config.getOrDefault("timeout", 30000);
                        client.setTcpNoDelay(true);
                        client.setSoTimeout(timeout);
                        clientThreads.submit(() -> handleClient(client, listener));
                    } catch (IOException e) {
                        if (running) {
                            LOGGER.warning("Error accepting client: " + e.getMessage());
                        }
                    }
                }
            } catch (IOException e) {
                LOGGER.severe("Error starting listener: " + e.getMessage());
            }
        }, "Skyfall-NetworkListener").start();
    }

    private static boolean checkConnectionThrottle(String ip) {
        long now = System.currentTimeMillis();
        int throttle = (int) config.getOrDefault("connection_throttle", 4000);
        int throttleLimit = (int) config.getOrDefault("connection_throttle_limit", 3);

        Long lastConnection = connectionThrottle.get(ip);
        if (lastConnection != null) {
            long timeDiff = now - lastConnection;
            if (timeDiff < throttle) {
                LOGGER.warning("Connection throttled for IP: " + ip);
                return false;
            }
        }

        connectionThrottle.put(ip, now);

        // Limpiar entradas antiguas
        connectionThrottle.entrySet().removeIf(entry ->
                (now - entry.getValue()) > throttle * 2
        );

        return true;
    }

    private static void handleClient(Socket client, Map<String, Object> listener) {
        String clientIP = client.getInetAddress().getHostAddress();

        try {
            DataInputStream in = new DataInputStream(new BufferedInputStream(client.getInputStream()));
            DataOutputStream out = new DataOutputStream(new BufferedOutputStream(client.getOutputStream()));

            int packetLength = readVarInt(in);
            if (packetLength <= 0 || packetLength > 2048) {
                client.close();
                return;
            }

            int packetId = readVarInt(in);

            if (packetId == 0x00) {
                int protocolVersion = readVarInt(in);
                String serverAddress = readString(in);
                int serverPort = in.readUnsignedShort();
                int nextState = readVarInt(in);

                if (nextState == 1) {
                    handleStatusRequest(in, out, listener);
                    out.flush();
                    client.close();
                    return;
                } else if (nextState == 2) {
                    playerIPs.put(serverAddress, clientIP);

                    boolean logPings = (boolean) config.getOrDefault("log_pings", true);
                    if (logPings) {
                        LOGGER.info("Player " + serverAddress + " [" + clientIP + "] is connecting...");
                    }

                    forwardToBackend(client, packetLength, packetId, protocolVersion,
                            serverAddress, serverPort, nextState, listener);
                    return;
                }
            }

            client.close();

        } catch (IOException e) {
            LOGGER.fine("Client disconnected during handshake: " + e.getMessage());
            closeQuietly(client);
        }
    }

    private static void handleStatusRequest(DataInputStream in, DataOutputStream out,
                                            Map<String, Object> listener) throws IOException {
        readVarInt(in);
        readVarInt(in);

        int totalOnline = onlinePlayers.values().stream().mapToInt(Integer::intValue).sum();
        int maxPlayers = (int) listener.getOrDefault("max_players", 100);
        String motd = (String) listener.getOrDefault("motd", "&6&lSkyfall Proxy\\n&7¡Servidor en línea!");
        motd = motd.replace("&", "§");

        String json = "{\"version\":{\"name\":\"Skyfall 1.20.1\",\"protocol\":763}," +
                "\"players\":{\"max\":" + maxPlayers + ",\"online\":" + totalOnline + ",\"sample\":[]}," +
                "\"description\":{\"text\":\"" + escapeJson(motd) + "\"}," +
                "\"favicon\":\"data:image/png;base64,\"," +
                "\"enforcesSecureChat\":false}";

        byte[] jsonBytes = json.getBytes(StandardCharsets.UTF_8);

        writeVarInt(out, getVarIntSize(0) + getVarIntSize(jsonBytes.length) + jsonBytes.length);
        writeVarInt(out, 0x00);
        writeString(out, json);
        out.flush();

        try {
            readVarInt(in);
            int pingId = readVarInt(in);
            if (pingId == 0x01) {
                long payload = in.readLong();
                writeVarInt(out, getVarIntSize(1) + 8);
                writeVarInt(out, 0x01);
                out.writeLong(payload);
                out.flush();
            }
        } catch (IOException ignored) {}
    }

    private static String escapeJson(String text) {
        return text.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static void forwardToBackend(Socket client, int handshakeLength, int handshakeId,
                                         int protocolVersion, String serverAddress, int serverPort,
                                         int nextState, Map<String, Object> listener) {
        List<String> priorities = (List<String>) listener.get("priorities");
        String fallback = priorities != null && !priorities.isEmpty() ? priorities.get(0) : "lobby";
        Socket backendSocket = null;

        try {
            Map<String, Map<String, Object>> servers = (Map<String, Map<String, Object>>) config.get("servers");
            Map<String, Object> backend = servers.get(fallback);

            if (backend == null) {
                sendDisconnect(client, "Backend server not configured");
                return;
            }

            String[] addr = backend.get("address").toString().split(":");
            String host = addr[0];
            int port = Integer.parseInt(addr[1]);

            if (!isServerOnline(host, port)) {
                fallback = findAvailableServer(fallback, priorities);
                if (fallback == null) {
                    LOGGER.warning("No available servers for player " + serverAddress);
                    sendDisconnect(client, "&cNo hay servidores disponibles");
                    return;
                }
                backend = servers.get(fallback);
                String[] newAddr = backend.get("address").toString().split(":");
                host = newAddr[0];
                port = Integer.parseInt(newAddr[1]);
            }

            backendSocket = new Socket(host, port);
            int timeout = (int) config.getOrDefault("timeout", 30000);
            backendSocket.setTcpNoDelay(true);
            backendSocket.setSoTimeout(timeout);

            String currentServer = playerServers.get(serverAddress);
            if (currentServer != null) {
                onlinePlayers.merge(currentServer, -1, Integer::sum);
            }

            onlinePlayers.merge(fallback, 1, Integer::sum);
            playerServers.put(serverAddress, fallback);

            DataOutputStream backendOut = new DataOutputStream(
                    new BufferedOutputStream(backendSocket.getOutputStream())
            );

            boolean ipForward = (boolean) config.getOrDefault("ip_forward", true);

            if (ipForward) {
                ByteArrayOutputStream handshakeBytes = new ByteArrayOutputStream();
                DataOutputStream handshakeOut = new DataOutputStream(handshakeBytes);

                writeVarInt(handshakeOut, protocolVersion);

                String forwardedAddress = serverAddress + "\u0000" +
                        client.getInetAddress().getHostAddress() + "\u0000" +
                        UUID.randomUUID().toString();
                writeString(handshakeOut, forwardedAddress);
                handshakeOut.writeShort(serverPort);
                writeVarInt(handshakeOut, nextState);

                ByteArrayOutputStream packetBytes = new ByteArrayOutputStream();
                DataOutputStream packetOut = new DataOutputStream(packetBytes);

                writeVarInt(packetOut, handshakeId);
                packetOut.write(handshakeBytes.toByteArray());

                byte[] packetData = packetBytes.toByteArray();

                writeVarInt(backendOut, packetData.length);
                backendOut.write(packetData);
            } else {
                writeVarInt(backendOut, handshakeLength);
                writeVarInt(backendOut, handshakeId);
                writeVarInt(backendOut, protocolVersion);
                writeString(backendOut, serverAddress);
                backendOut.writeShort(serverPort);
                writeVarInt(backendOut, nextState);
            }

            backendOut.flush();

            String finalFallback = fallback;
            Socket finalBackendSocket = backendSocket;

            clientThreads.submit(() -> {
                try {
                    InputStream clientIn = client.getInputStream();
                    OutputStream backendOut2 = finalBackendSocket.getOutputStream();
                    forwardData(clientIn, backendOut2);
                } catch (IOException e) {
                    LOGGER.fine("Client to backend connection closed for " + serverAddress);
                } finally {
                    closeQuietly(finalBackendSocket);
                    onlinePlayers.merge(finalFallback, -1, Integer::sum);
                    playerServers.remove(serverAddress, finalFallback);
                    playerIPs.remove(serverAddress);
                }
            });

            clientThreads.submit(() -> {
                try {
                    InputStream backendIn = finalBackendSocket.getInputStream();
                    OutputStream clientOut = client.getOutputStream();
                    forwardData(backendIn, clientOut);
                } catch (IOException e) {
                    LOGGER.fine("Backend to client connection closed for " + serverAddress);
                } finally {
                    closeQuietly(client);
                }
            });

        } catch (IOException e) {
            LOGGER.warning("Error forwarding " + serverAddress + " to backend: " + e.getMessage());
            closeQuietly(client);
            closeQuietly(backendSocket);
            if (fallback != null) {
                onlinePlayers.merge(fallback, -1, Integer::sum);
                playerServers.values().removeIf(fallback::equals);
                playerIPs.remove(serverAddress);
            }
        }
    }

    private static String findAvailableServer(String excludedServer, List<String> priorities) {
        Map<String, Map<String, Object>> servers = (Map<String, Map<String, Object>>) config.get("servers");

        if (priorities != null) {
            for (String server : priorities) {
                if (server.equals(excludedServer)) continue;

                Map<String, Object> backend = servers.get(server);
                if (backend != null) {
                    String[] addr = backend.get("address").toString().split(":");
                    String host = addr[0];
                    int port = Integer.parseInt(addr[1]);

                    if (isServerOnline(host, port)) {
                        return server;
                    }
                }
            }
        }

        return null;
    }

    private static void sendDisconnect(Socket client, String message) {
        try {
            DataOutputStream out = new DataOutputStream(client.getOutputStream());
            String json = "{\"text\":\"" + escapeJson(message.replace("&", "§")) + "\"}";
            byte[] jsonBytes = json.getBytes(StandardCharsets.UTF_8);

            writeVarInt(out, getVarIntSize(0) + getVarIntSize(jsonBytes.length) + jsonBytes.length);
            writeVarInt(out, 0x00);
            writeString(out, json);
            out.flush();

            client.close();
        } catch (IOException e) {
            LOGGER.fine("Error sending disconnect: " + e.getMessage());
        }
    }

    private static boolean isServerOnline(String host, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), 2000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private static void forwardData(InputStream in, OutputStream out) {
        try {
            byte[] buffer = new byte[8192];
            int len;
            while ((len = in.read(buffer)) != -1) {
                out.write(buffer, 0, len);
                out.flush();
            }
        } catch (IOException e) {
            // Connection closed normally
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            LOGGER.fine("Error closing socket: " + e.getMessage());
        }
    }

    private static int readVarInt(DataInputStream in) throws IOException {
        int value = 0;
        int position = 0;
        byte currentByte;

        while (true) {
            currentByte = in.readByte();
            value |= (currentByte & 0x7F) << position;

            if ((currentByte & 0x80) == 0) break;

            position += 7;

            if (position >= 32) throw new IOException("VarInt too large");
        }

        return value;
    }

    private static void writeVarInt(DataOutputStream out, int value) throws IOException {
        while (true) {
            if ((value & ~0x7F) == 0) {
                out.writeByte(value);
                return;
            }

            out.writeByte((value & 0x7F) | 0x80);
            value >>>= 7;
        }
    }

    private static int getVarIntSize(int value) {
        int size = 0;
        while (true) {
            size++;
            if ((value & ~0x7F) == 0) return size;
            value >>>= 7;
        }
    }

    private static String readString(DataInputStream in) throws IOException {
        int length = readVarInt(in);
        if (length < 0 || length > 32767) {
            throw new IOException("String length out of bounds: " + length);
        }
        byte[] bytes = new byte[length];
        in.readFully(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static void writeString(DataOutputStream out, String s) throws IOException {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 32767) {
            throw new IOException("String too long: " + bytes.length);
        }
        writeVarInt(out, bytes.length);
        out.write(bytes);
    }

    private static void startConsole() {
        Scanner scanner = new Scanner(System.in);
        while (running) {
            try {
                if (guiMode) {
                    System.out.print("> ");
                }

                if (!scanner.hasNextLine()) {
                    break;
                }

                String line = scanner.nextLine().trim();

                if (line.isEmpty()) {
                    continue;
                }

                String[] parts = line.split(" ");
                String command = parts[0].toLowerCase();

                boolean logCommands = (boolean) config.getOrDefault("log_commands", false);
                if (logCommands) {
                    LOGGER.info("Executed command: " + line);
                }

                // Manejar comandos del PluginDeveloperTools usando reflection
                boolean handledByPlugin = false;
                if (command.equals("devtools") || command.equals("pdt") ||
                        command.equals("plugin") || command.equals("pl")) {

                    handledByPlugin = handlePluginCommand(command, parts);
                }

                if (handledByPlugin) {
                    continue; // El plugin ya manejó el comando
                }

                // Comandos normales de Skyfall
                switch (command) {
                    case "end":
                    case "stop":
                        handleShutdown();
                        break;

                    case "reload":
                        LOGGER.info("Reloading configuration...");
                        if (loadConfig(getConfigFile())) {
                            LOGGER.info("Configuration reloaded successfully!");
                        } else {
                            LOGGER.warning("Failed to reload configuration!");
                        }
                        break;

                    case "list":
                    case "glist":
                        int total = onlinePlayers.values().stream().mapToInt(Integer::intValue).sum();
                        LOGGER.info("Online players: " + total);
                        onlinePlayers.forEach((server, count) ->
                                LOGGER.info(" - " + server + ": " + count + " player(s)"));
                        break;

                    case "find":
                        if (parts.length >= 2) {
                            handleFindCommand(parts[1]);
                        } else {
                            LOGGER.warning("Usage: find <player>");
                        }
                        break;

                    case "servers":
                        handleServersCommand();
                        break;

                    case "send":
                        if (parts.length >= 3) {
                            handleSendCommand(parts[1], parts[2]);
                        } else {
                            LOGGER.warning("Usage: send <player> <server>");
                        }
                        break;

                    case "plugins":
                        handlePluginsCommand();
                        break;

                    case "help":
                        showHelp();
                        break;

                    case "version":
                    case "ver":
                        LOGGER.info("This server is running Skyfall version " + VERSION);
                        break;

                    case "ip":
                        if (parts.length >= 2) {
                            handleIpCommand(parts[1]);
                        } else {
                            LOGGER.warning("Usage: ip <player>");
                        }
                        break;

                    case "alert":
                        if (parts.length >= 2) {
                            String message = String.join(" ", Arrays.copyOfRange(parts, 1, parts.length));
                            LOGGER.info("Broadcasting: " + message);
                        } else {
                            LOGGER.warning("Usage: alert <message>");
                        }
                        break;

                    default:
                        LOGGER.warning("Unknown command: " + line + ". Type 'help' for available commands.");
                }
            } catch (Exception e) {
                if (running) {
                    LOGGER.severe("Console error: " + e.getMessage());
                }
            }
        }
        scanner.close();
    }

    // Nuevo método para manejar comandos de plugins usando reflection
    private static boolean handlePluginCommand(String command, String[] parts) {
        for (SkyfallPlugin plugin : loadedPlugins) {
            try {
                // Usar reflection para detectar si el plugin tiene el método handleCommand
                Method handleCommandMethod = plugin.getClass().getMethod("handleCommand", String.class, String[].class);

                // Llamar al método handleCommand del plugin
                Object result = handleCommandMethod.invoke(plugin, command, Arrays.copyOfRange(parts, 1, parts.length));

                if (result instanceof Boolean && (Boolean) result) {
                    return true; // El plugin manejó el comando
                }
            } catch (NoSuchMethodException e) {
                // El plugin no tiene método handleCommand, continuar con el siguiente
                continue;
            } catch (Exception e) {
                LOGGER.warning("Error executing plugin command: " + e.getMessage());
            }
        }
        return false; // Ningún plugin manejó el comando
    }

    private static void handleShutdown() {
        LOGGER.info("Shutting down proxy...");
        LOGGER.info("Closing pending connections");
        int totalPlayers = onlinePlayers.values().stream().mapToInt(Integer::intValue).sum();
        LOGGER.info("Disconnecting " + totalPlayers + " connections");
        running = false;

        LOGGER.info("Disabling plugins");
        for (SkyfallPlugin plugin : loadedPlugins) {
            try {
                plugin.onDisable();
                LOGGER.info("Disabled plugin " + plugin.getName());
            } catch (Exception e) {
                LOGGER.severe("Error disabling plugin " + plugin.getName() + ": " + e.getMessage());
            }
        }

        clientThreads.shutdown();
        try {
            if (!clientThreads.awaitTermination(5, TimeUnit.SECONDS)) {
                clientThreads.shutdownNow();
                if (!clientThreads.awaitTermination(5, TimeUnit.SECONDS)) {
                    LOGGER.warning("Thread pool did not terminate");
                }
            }
        } catch (InterruptedException e) {
            clientThreads.shutdownNow();
            Thread.currentThread().interrupt();
        }

        if (serverSocket != null && !serverSocket.isClosed()) {
            try {
                serverSocket.close();
            } catch (IOException e) {
                LOGGER.severe("Error closing server socket: " + e.getMessage());
            }
        }

        LOGGER.info("Closing IO threads");
        LOGGER.info("Thank you and goodbye");
        System.exit(0);
    }

    private static void handleFindCommand(String player) {
        String server = playerServers.get(player);
        if (server != null) {
            String ip = playerIPs.getOrDefault(player, "unknown");
            LOGGER.info(player + " is on " + server + " [" + ip + "]");
        } else {
            LOGGER.warning("Player " + player + " is not online");
        }
    }

    private static void handleServersCommand() {
        Map<String, Map<String, Object>> servers = (Map<String, Map<String, Object>>) config.get("servers");
        if (servers == null || servers.isEmpty()) {
            LOGGER.info("No servers configured");
            return;
        }

        LOGGER.info("Available servers:");
        servers.forEach((name, info) -> {
            int online = onlinePlayers.getOrDefault(name, 0);
            String address = (String) info.get("address");
            boolean restricted = (boolean) info.getOrDefault("restricted", false);

            String[] addrParts = address.split(":");
            boolean isOnline = isServerOnline(addrParts[0], Integer.parseInt(addrParts[1]));
            String status = isOnline ? "ONLINE" : "OFFLINE";

            LOGGER.info(" - " + name + " (" + online + " players) " +
                    status + (restricted ? " [RESTRICTED]" : ""));
        });
    }

    private static void handleSendCommand(String player, String targetServer) {
        if (!playerServers.containsKey(player)) {
            LOGGER.warning("Player " + player + " is not online");
            return;
        }

        Map<String, Map<String, Object>> servers = (Map<String, Map<String, Object>>) config.get("servers");
        if (servers == null || !servers.containsKey(targetServer)) {
            LOGGER.warning("Server " + targetServer + " does not exist");
            return;
        }

        String currentServer = playerServers.get(player);
        if (currentServer.equals(targetServer)) {
            LOGGER.warning("Player " + player + " is already on " + targetServer);
            return;
        }

        LOGGER.info("Sending " + player + " from " + currentServer + " to " + targetServer);

        onlinePlayers.merge(currentServer, -1, Integer::sum);
        playerServers.put(player, targetServer);
        onlinePlayers.merge(targetServer, 1, Integer::sum);

        LOGGER.info("Player " + player + " successfully sent to " + targetServer);
    }

    private static void handleIpCommand(String player) {
        String ip = playerIPs.get(player);
        String server = playerServers.get(player);

        if (ip != null && server != null) {
            LOGGER.info(player + " is connected from " + ip + " on " + server);
        } else {
            LOGGER.warning("Player " + player + " is not online");
        }
    }

    private static void handlePluginsCommand() {
        if (loadedPlugins.isEmpty()) {
            LOGGER.info("No plugins loaded");
        } else {
            LOGGER.info("Plugins (" + loadedPlugins.size() + "):");
            for (SkyfallPlugin plugin : loadedPlugins) {
                LOGGER.info(" - " + plugin.getName() + " v" + plugin.getVersion());
            }
        }
    }

    private static void showHelp() {
        LOGGER.info("Available commands:");
        LOGGER.info(" - end/stop: Shutdown the proxy");
        LOGGER.info(" - reload: Reload configuration");
        LOGGER.info(" - list/glist: Show online players per server");
        LOGGER.info(" - find <player>: Find a player's server");
        LOGGER.info(" - servers: List all available servers");
        LOGGER.info(" - send <player> <server>: Send player to server");
        LOGGER.info(" - ip <player>: Show player's IP address");
        LOGGER.info(" - alert <message>: Broadcast a message");
        LOGGER.info(" - plugins: List loaded plugins");
        LOGGER.info(" - version: Show version information");
        LOGGER.info(" - help: Show this help message");
        LOGGER.info(" - devtools/pdt: Plugin development tools");
        LOGGER.info(" - plugin/pl: Plugin management commands");
    }

    // Interface para plugins
    public interface SkyfallPlugin {
        void onEnable();
        void onDisable();
        String getName();
        String getVersion();
        default void setAPI(SkyfallAPI api) {}
        default void setDataFolder(File dataFolder) {}

        // Nuevo método opcional para manejar comandos
        default boolean handleCommand(String command, String[] args) {
            return false;
        }
    }

    // Clase API para plugins
    public static class SkyfallAPI {
        public Map<String, Integer> getOnlinePlayers() {
            return new HashMap<>(onlinePlayers);
        }

        public Map<String, String> getPlayerServers() {
            return new HashMap<>(playerServers);
        }

        public Map<String, String> getPlayerIPs() {
            return new HashMap<>(playerIPs);
        }

        public int getTotalPlayers() {
            return onlinePlayers.values().stream().mapToInt(Integer::intValue).sum();
        }

        public boolean isServerOnline(String serverName) {
            Map<String, Map<String, Object>> servers = (Map<String, Map<String, Object>>) config.get("servers");
            if (servers != null && servers.containsKey(serverName)) {
                Map<String, Object> server = servers.get(serverName);
                String[] addr = ((String) server.get("address")).split(":");
                String host = addr[0];
                int port = Integer.parseInt(addr[1]);
                return Skyfall.isServerOnline(host, port);
            }
            return false;
        }

        public void sendMessageToPlayer(String player, String message) {
            LOGGER.info("[API] Message to " + player + ": " + message);
        }

        public boolean sendPlayerToServer(String player, String server) {
            if (playerServers.containsKey(player) && isServerOnline(server)) {
                handleSendCommand(player, server);
                return true;
            }
            return false;
        }

        public String getServerMotd(String server) {
            Map<String, Map<String, Object>> servers = (Map<String, Map<String, Object>>) config.get("servers");
            if (servers != null && servers.containsKey(server)) {
                return (String) servers.get(server).get("motd");
            }
            return null;
        }

        public Set<String> getBannedIPs() {
            return new HashSet<>(bannedIPs);
        }

        public Map<String, Object> getConfig() {
            return new HashMap<>(config);
        }

        public Logger getLogger() {
            return LOGGER;
        }
    }
}