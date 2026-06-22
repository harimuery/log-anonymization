package com.example.anonymization.core.infrastructure.config;

import com.example.anonymization.api.model.MaskingRule;
import com.example.anonymization.api.port.RuleLoadPort;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * 本地文件规则加载适配器 —— {@link RuleLoadPort} 的本地 YAML 文件实现。
 *
 * <p>属于基础设施层（infrastructure/config），从 classpath 或文件系统加载脱敏规则 YAML 文件，
 * 并通过 {@link YamlRuleParser} 解析为 {@link MaskingRule} 列表。
 *
 * <p>支持两种路径格式：
 * <ul>
 *   <li>{@code classpath:xxx.yml} —— 从类路径加载；</li>
 *   <li>{@code file:/path/to/xxx.yml} 或绝对路径 —— 从文件系统加载。</li>
 * </ul>
 *
 * <p>动态刷新：通过 {@link java.nio.file.WatchService} 监听文件变更（仅文件系统路径支持），
 * 变更时回调所有已注册的 {@link Consumer}。
 *
 * @author log-anonymization
 * @since 1.0.0
 */
public class LocalFileRuleLoadAdapter implements RuleLoadPort {

    private static final String CLASSPATH_PREFIX = "classpath:";

    private final String filePath;
    private final YamlRuleParser yamlRuleParser;
    private final List<Consumer<List<MaskingRule>>> listeners = new ArrayList<>();
    private volatile Thread watchThread;

    /**
     * 构造本地文件规则加载器。
     *
     * @param filePath 规则文件路径（classpath: 或 file: 前缀）
     */
    public LocalFileRuleLoadAdapter(String filePath) {
        this.filePath = filePath;
        this.yamlRuleParser = new YamlRuleParser();
    }

    /**
     * 同步加载规则列表。
     *
     * <p>根据路径前缀选择加载方式，读取 YAML 内容后通过 {@link YamlRuleParser} 解析。
     *
     * @return 规则列表
     */
    @Override
    public List<MaskingRule> loadRules() {
        try {
            String content = readFileContent();
            if (content == null || content.isBlank()) {
                return List.of();
            }
            return yamlRuleParser.parse(content);
        } catch (IOException e) {
            return List.of();
        }
    }

    /**
     * 注册规则变更监听器。
     *
     * <p>当文件变更时，回调所有监听器，
     * 由 {@link com.example.anonymization.core.domain.ThreadSafeRuleManager}
     * 完成原子替换。
     *
     * <p>首次注册监听器时启动文件监听线程（仅文件系统路径支持）。
     *
     * @param listener 变更监听器
     */
    @Override
    public void onRuleChange(Consumer<List<MaskingRule>> listener) {
        listeners.add(listener);
        if (listeners.size() == 1 && !filePath.startsWith(CLASSPATH_PREFIX)) {
            startFileWatcher();
        }
    }

    private String readFileContent() throws IOException {
        if (filePath.startsWith(CLASSPATH_PREFIX)) {
            String resourcePath = filePath.substring(CLASSPATH_PREFIX.length());
            try (InputStream is = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
                if (is == null) return null;
                try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    return reader.lines().collect(Collectors.joining("\n"));
                }
            }
        } else {
            return Files.readString(Path.of(filePath), StandardCharsets.UTF_8);
        }
    }

    private void startFileWatcher() {
        Path path = Path.of(filePath);
        if (!Files.exists(path)) return;
        Path parent = path.getParent();
        if (parent == null) return;

        watchThread = new Thread(() -> {
            try (java.nio.file.WatchService watchService =
                java.nio.file.FileSystems.getDefault().newWatchService()) {
                parent.register(watchService,
                    java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY);
                while (!Thread.currentThread().isInterrupted()) {
                    java.nio.file.WatchKey key = watchService.take();
                    for (java.nio.file.WatchEvent<?> event : key.pollEvents()) {
                        if (event.context() instanceof Path changedPath
                            && changedPath.toString().equals(path.getFileName().toString())) {
                            notifyListeners();
                        }
                    }
                    key.reset();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                if (e instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
            }
        }, "rule-file-watcher");
        watchThread.setDaemon(true);
        watchThread.start();
    }

    private void notifyListeners() {
        try {
            List<MaskingRule> newRules = loadRules();
            for (Consumer<List<MaskingRule>> listener : listeners) {
                listener.accept(newRules);
            }
        } catch (Exception e) {
            // 通知失败不阻塞
        }
    }
}