/**
 * @file marketstream.cpp
 * @brief Production market data provider (C++ equivalent to Python marketstream)
 * @author jessiondiwangan@gmail.com
 * @date 2025
 * 
 * LatentSpeed MarketStream - High-performance market data provider
 * Streams preprocessed market data via ZMQ for trading_engine_server consumption
 * 
 * Architecture:
 *   Exchange WebSocket → MarketStream → ZMQ (preprocessed) → trading_engine_server
 * 
 * Difference from Python marketstream:
 *   - No Redis Streams (direct ZMQ only for ultra-low latency)
 *   - Native C++ performance
 *   - Same data format and preprocessing features
 */

#include "feed_handler.h"
#include <yaml-cpp/yaml.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <signal.h>
#include <fstream>
#include <iostream>

using namespace latentspeed;

// Global feed handler
std::unique_ptr<FeedHandler> g_feed_handler;
std::atomic<bool> g_shutdown{false};

void signal_handler(int signum) {
    spdlog::info("Received signal {}, shutting down...", signum);
    g_shutdown.store(true);
    if (g_feed_handler) {
        g_feed_handler->stop();
    }
}

// Production callback for market data
class MarketStreamCallback : public MarketDataCallbacks {
public:
    void on_trade(const MarketTick& tick) override {
        spdlog::debug("[TRADE] {}:{} @ ${:.2f} x {:.4f} {}",
                     tick.exchange.c_str(), tick.symbol.c_str(),
                     tick.price, tick.amount, tick.side.c_str());
        trade_count_++;
    }

    void on_orderbook(const OrderBookSnapshot& snapshot) override {
        spdlog::debug("[BOOK] {}:{} - Mid: ${:.2f} Spread: {:.2f} bps",
                     snapshot.exchange.c_str(), snapshot.symbol.c_str(),
                     snapshot.midpoint,
                     snapshot.relative_spread * 10000);
        book_count_++;
    }
    
    void on_error(const std::string& error) override {
        spdlog::error("[ERROR] {}", error);
    }
    
    uint64_t get_trade_count() const { return trade_count_.load(); }
    uint64_t get_book_count() const { return book_count_.load(); }
    
private:
    std::atomic<uint64_t> trade_count_{0};
    std::atomic<uint64_t> book_count_{0};
};

// Parse log level from string
spdlog::level::level_enum parse_log_level(const std::string& level_str) {
    if (level_str == "trace") return spdlog::level::trace;
    if (level_str == "debug") return spdlog::level::debug;
    if (level_str == "info") return spdlog::level::info;
    if (level_str == "warn") return spdlog::level::warn;
    if (level_str == "error") return spdlog::level::err;
    if (level_str == "critical") return spdlog::level::critical;
    return spdlog::level::info;
}

int main(int argc, char** argv) {
    // Default config path
    std::string config_path = "config.yml";
    
    // Parse command line arguments
    if (argc > 1) {
        config_path = argv[1];
    }
    
    // Check if config file exists
    if (!std::ifstream(config_path).good()) {
        std::cerr << "Config file not found: " << config_path << std::endl;
        std::cerr << "Usage: " << argv[0] << " [config.yml]" << std::endl;
        return 1;
    }
    
    try {
        // Load YAML config
        YAML::Node config = YAML::LoadFile(config_path);
        
        // Setup logging
        std::vector<spdlog::sink_ptr> sinks;
        sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
        
        if (config["log"]) {
            if (config["log"]["filename"]) {
                std::string log_file = config["log"]["filename"].as<std::string>();
                sinks.push_back(std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file, true));
            }
        }
        
        auto logger = std::make_shared<spdlog::logger>("marketstream", begin(sinks), end(sinks));
        spdlog::set_default_logger(logger);
        
        // Set log level
        if (config["log"] && config["log"]["level"]) {
            std::string level = config["log"]["level"].as<std::string>();
            spdlog::set_level(parse_log_level(level));
        } else {
            spdlog::set_level(spdlog::level::info);
        }
        
        // Signal handlers
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        
        spdlog::info("===========================================");
        spdlog::info("LatentSpeed MarketStream");
        spdlog::info("Production Market Data Provider (C++)");
        spdlog::info("Config: {}", config_path);
        spdlog::info("===========================================");
        
        // Configure FeedHandler from config
        FeedHandler::Config feed_config;
        
        if (config["zmq"]) {
            feed_config.zmq_trades_port = config["zmq"]["port"].as<int>(5556);
            feed_config.zmq_books_port = feed_config.zmq_trades_port + 1;
            feed_config.window_size = config["zmq"]["window_size"].as<int>(20);
            feed_config.depth_levels = config["zmq"]["depth_levels"].as<int>(10);
            // Deltas/ckpts toggle: emit deltas and checkpoints (suppress snapshots) when enabled
            if (config["zmq"]["deltas"]) {
                auto dlt = config["zmq"]["deltas"];
                bool enabled = dlt["enabled"].as<bool>(false);
                feed_config.emit_delta = enabled;
                feed_config.emit_ckpt = enabled;
                feed_config.emit_snapshot = !enabled;
                feed_config.ckpt_every_ms = dlt["checkpoint_every_ms"].as<int>(1000);
            }
        }
        
        g_feed_handler = std::make_unique<FeedHandler>(feed_config);
        
        // Shared callbacks for all feeds
        auto callbacks = std::make_shared<MarketStreamCallback>();
        
        // Parse and add feeds
        if (!config["feeds"] || !config["feeds"].IsSequence()) {
            spdlog::error("No feeds configured in config file");
            return 1;
        }
        
        int total_symbols = 0;
        for (const auto& feed_node : config["feeds"]) {
            ExchangeConfig exchange_config;
            
            // Parse exchange name
            exchange_config.name = feed_node["exchange"].as<std::string>();
            
            // Parse symbols
            if (feed_node["symbols"] && feed_node["symbols"].IsSequence()) {
                for (const auto& sym : feed_node["symbols"]) {
                    exchange_config.symbols.push_back(sym.as<std::string>());
                }
            }
            
            // Parse other config
            exchange_config.enable_trades = feed_node["enable_trades"].as<bool>(true);
            exchange_config.enable_orderbook = feed_node["enable_orderbook"].as<bool>(true);
            exchange_config.snapshots_only = feed_node["snapshots_only"].as<bool>(false);
            exchange_config.snapshot_interval = feed_node["snapshot_interval"].as<int>(1);
            
            spdlog::info("Adding {} feed: {} symbols", 
                        exchange_config.name, exchange_config.symbols.size());
            
            total_symbols += exchange_config.symbols.size();
            
            // Add feed
            g_feed_handler->add_feed(exchange_config, callbacks);
        }
        
        // Start all feeds
        spdlog::info("Starting {} feed(s) with {} total symbols...", 
                    config["feeds"].size(), total_symbols);
        g_feed_handler->start();
        
        spdlog::info("===========================================");
        spdlog::info("Streaming market data (Press Ctrl+C to stop)");
        if (config["zmq"] && config["zmq"]["enabled"].as<bool>(true)) {
            spdlog::info("ZMQ Output:");
            spdlog::info("  - Trades:     tcp://{}:{}", 
                        config["zmq"]["host"].as<std::string>("127.0.0.1"),
                        feed_config.zmq_trades_port);
            if (feed_config.emit_delta || feed_config.emit_ckpt) {
                spdlog::info("  - Orderbooks (delta/ckpt): tcp://{}:{}", 
                            config["zmq"]["host"].as<std::string>("127.0.0.1"),
                            feed_config.zmq_books_port);
            } else if (feed_config.emit_snapshot) {
                spdlog::info("  - Orderbooks (snapshots):  tcp://{}:{}", 
                            config["zmq"]["host"].as<std::string>("127.0.0.1"),
                            feed_config.zmq_books_port);
            } else {
                spdlog::info("  - Orderbooks: disabled");
            }
        }
        spdlog::info("===========================================\n");
        
        // Stats loop
        auto start_time = std::chrono::steady_clock::now();
        int stats_interval = 30; // seconds (less verbose for production)
        
        while (!g_shutdown.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(stats_interval));
            
            if (!g_shutdown.load()) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
                
                spdlog::info("--- Stats ({}s) ---", elapsed);
                spdlog::info("Trades: {} ({:.1f}/sec)", 
                           callbacks->get_trade_count(),
                           elapsed > 0 ? static_cast<double>(callbacks->get_trade_count()) / elapsed : 0.0);
                spdlog::info("Books: {} ({:.1f}/sec)", 
                           callbacks->get_book_count(),
                           elapsed > 0 ? static_cast<double>(callbacks->get_book_count()) / elapsed : 0.0);
            }
        }
        
        spdlog::info("\nStopping all feeds...");
        g_feed_handler->stop();
        
    } catch (const YAML::Exception& e) {
        spdlog::error("YAML error: {}", e.what());
        return 1;
    } catch (const std::exception& e) {
        spdlog::error("Fatal error: {}", e.what());
        return 1;
    }
    
    spdlog::info("Shutdown complete");
    return 0;
}
