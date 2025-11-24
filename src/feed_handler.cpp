/**
 * @file feed_handler.cpp
 * @brief Multi-exchange feed handler implementation
 * @author jessiondiwangan@gmail.com
 * @date 2025
 */

#include "feed_handler.h"
#include <spdlog/spdlog.h>
#include <fstream>
#include <yaml-cpp/yaml.h>

namespace latentspeed {

void FeedHandler::add_feed(
    const ExchangeConfig& exchange_config,
    std::shared_ptr<MarketDataCallbacks> callbacks
) {
    spdlog::info("[FeedHandler] Adding feed: {} with {} symbols", 
                 exchange_config.name, exchange_config.symbols.size());
    
    FeedEntry entry;
    entry.config = exchange_config;
    entry.callbacks = callbacks;
    
    // Create exchange instance
    entry.exchange = ExchangeFactory::create(exchange_config.name);
    
    // Create market data provider for this exchange
    entry.provider = std::make_unique<MarketDataProvider>(
        exchange_config.name,
        exchange_config.symbols,
        entry.exchange.get(),  // Pass exchange interface
        exchange_config.reconnect_attempts,
        exchange_config.reconnect_delay_ms,
        exchange_config.subscription_delay_ms
    );
    // Configure provider outputs from handler config (snapshot vs delta/ckpt)
    try {
        entry.provider->configure_outputs(
            config_.emit_snapshot,
            config_.emit_delta,
            config_.emit_ckpt,
            config_.ckpt_every_ms,
            config_.depth_levels
        );
    } catch (const std::exception&){ /* best-effort */ }
    
    // Set callbacks if provided
    if (callbacks) {
        entry.provider->set_callbacks(callbacks);
    }
    
    providers_.push_back(std::move(entry));
    
    spdlog::info("[FeedHandler] Feed added successfully: {}", exchange_config.name);
}

void FeedHandler::start() {
    if (running_.exchange(true)) {
        spdlog::warn("[FeedHandler] Already running");
        return;
    }
    
    spdlog::info("[FeedHandler] Starting {} feed(s)...", providers_.size());
    
    // Initialize and start each provider
    for (auto& entry : providers_) {
        spdlog::info("[FeedHandler] Initializing feed: {}", entry.config.name);
        
        if (!entry.provider->initialize()) {
            spdlog::error("[FeedHandler] Failed to initialize feed: {}", entry.config.name);
            continue;
        }
        
        entry.provider->start();
    }
    
    spdlog::info("[FeedHandler] All feeds started");
}

void FeedHandler::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    
    spdlog::info("[FeedHandler] Stopping {} feed(s)...", providers_.size());
    
    // Stop all providers
    for (auto& entry : providers_) {
        spdlog::info("[FeedHandler] Stopping feed: {}", entry.config.name);
        entry.provider->stop();
    }
    
    spdlog::info("[FeedHandler] All feeds stopped");
}

std::vector<FeedHandler::FeedStats> FeedHandler::get_stats() const {
    std::vector<FeedStats> stats;
    
    for (const auto& entry : providers_) {
        FeedStats feed_stats;
        feed_stats.exchange = entry.config.name;
        
        const auto& provider_stats = entry.provider->get_stats();
        // Load atomic values
        feed_stats.messages_received = provider_stats.trades_processed.load() + 
                                       provider_stats.orderbooks_processed.load();
        feed_stats.messages_published = provider_stats.messages_published.load();
        feed_stats.errors = provider_stats.errors.load();
        
        stats.push_back(feed_stats);
    }
    
    return stats;
}

// ============================================================================
// ConfigLoader Implementation
// ============================================================================

ConfigLoader::LoadedConfig ConfigLoader::load_from_yaml(const std::string& path) {
    spdlog::info("[ConfigLoader] Loading configuration from: {}", path);
    
    LoadedConfig result;
    
    try {
        YAML::Node config = YAML::LoadFile(path);
        
        // Load ZMQ configuration
        if (config["zmq"]) {
            auto zmq = config["zmq"];
            if (zmq["port"]) {
                result.handler_config.zmq_trades_port = zmq["port"].as<int>();
                result.handler_config.zmq_books_port = zmq["port"].as<int>() + 1;
            }
            if (zmq["window_size"]) {
                result.handler_config.window_size = zmq["window_size"].as<int>();
            }
            if (zmq["depth_levels"]) {
                result.handler_config.depth_levels = zmq["depth_levels"].as<int>();
            }
            // Delta/ckpt sub-config
            if (zmq["deltas"]) {
                auto dlt = zmq["deltas"];
                bool enabled = dlt["enabled"].as<bool>(false);
                result.handler_config.emit_delta = enabled;
                result.handler_config.emit_ckpt = enabled;
                result.handler_config.emit_snapshot = !enabled;
                if (dlt["checkpoint_every_ms"]) {
                    result.handler_config.ckpt_every_ms = dlt["checkpoint_every_ms"].as<int>(1000);
                }
            }
        }
        
        // Load backend multiprocessing setting (ignored in C++)
        if (config["backend_multiprocessing"]) {
            result.handler_config.backend_multiprocessing = 
                config["backend_multiprocessing"].as<bool>();
        }
        
        // Load feeds
        if (config["feeds"]) {
            for (const auto& feed_node : config["feeds"]) {
                ExchangeConfig exchange_config;
                
                if (feed_node["exchange"]) {
                    exchange_config.name = feed_node["exchange"].as<std::string>();
                }
                
                if (feed_node["symbols"]) {
                    for (const auto& sym : feed_node["symbols"]) {
                        exchange_config.symbols.push_back(sym.as<std::string>());
                    }
                }
                
                if (feed_node["snapshots_only"]) {
                    exchange_config.snapshots_only = feed_node["snapshots_only"].as<bool>();
                }
                
                if (feed_node["snapshot_interval"]) {
                    exchange_config.snapshot_interval = feed_node["snapshot_interval"].as<int>();
                }

                if (feed_node["subscription_delay_ms"]) {
                    exchange_config.subscription_delay_ms = feed_node["subscription_delay_ms"].as<int>();
                }

                result.feeds.push_back(exchange_config);
                
                spdlog::info("[ConfigLoader] Loaded feed: {} with {} symbols",
                           exchange_config.name, exchange_config.symbols.size());
            }
        }
        
        spdlog::info("[ConfigLoader] Configuration loaded successfully: {} feeds", 
                    result.feeds.size());
        
    } catch (const YAML::Exception& e) {
        spdlog::error("[ConfigLoader] YAML error: {}", e.what());
        throw std::runtime_error("Failed to load config: " + std::string(e.what()));
    }
    
    return result;
}

void ConfigLoader::create_example_config(const std::string& path) {
    std::ofstream file(path);
    
    if (!file.is_open()) {
        throw std::runtime_error("Failed to create config file: " + path);
    }
    
    file << R"(# Market Data Provider Configuration
# Similar to Python cryptofeed config.yml

zmq:
  enabled: true
  host: 127.0.0.1
  port: 5556  # trades port, books will use port+1 (5557)
  window_size: 20
  depth_levels: 10

log:
  level: INFO

backend_multiprocessing: false  # Not used in C++ (always multi-threaded)

feeds:
  - exchange: bybit
    symbols:
      - BTC-USDT
      - ETH-USDT
      - SOL-USDT
    snapshots_only: true
    snapshot_interval: 1

  - exchange: binance
    symbols:
      - BTC-USDT
      - ETH-USDT
    snapshots_only: true
    snapshot_interval: 1
)";
    
    file.close();
    spdlog::info("[ConfigLoader] Example config created: {}", path);
}

} // namespace latentspeed
