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
#include <array>
#include <algorithm>
#include <vector>

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

// Lock-free latency tracker using circular buffer
class LatencyTracker {
public:
    LatencyTracker() : write_idx_(0) {
        samples_.fill(0);
    }

    // Lock-free: record latency (called from hot path)
    void record(uint64_t latency_ns) {
        // Use relaxed ordering for maximum performance
        uint32_t idx = write_idx_.fetch_add(1, std::memory_order_relaxed) % BUFFER_SIZE;
        samples_[idx] = latency_ns;
    }

    // Compute statistics (called from stats thread, NOT in hot path)
    struct Stats {
        uint64_t min_us = 0;
        uint64_t max_us = 0;
        uint64_t p50_us = 0;
        uint64_t p95_us = 0;
        uint64_t p99_us = 0;
        double avg_us = 0.0;
        uint32_t count = 0;
    };

    Stats compute_stats() {
        Stats stats;
        std::vector<uint64_t> sorted_samples;
        sorted_samples.reserve(BUFFER_SIZE);

        // Copy samples to local vector
        uint32_t current_idx = write_idx_.load(std::memory_order_relaxed);
        for (uint32_t i = 0; i < BUFFER_SIZE; ++i) {
            uint64_t sample = samples_[i];
            if (sample > 0) {  // Skip uninitialized slots
                sorted_samples.push_back(sample);
            }
        }

        if (sorted_samples.empty()) {
            return stats;
        }

        stats.count = sorted_samples.size();

        // Sort for percentile calculation
        std::sort(sorted_samples.begin(), sorted_samples.end());

        // Convert to microseconds
        stats.min_us = sorted_samples.front() / 1000;
        stats.max_us = sorted_samples.back() / 1000;
        stats.p50_us = sorted_samples[sorted_samples.size() * 50 / 100] / 1000;
        stats.p95_us = sorted_samples[sorted_samples.size() * 95 / 100] / 1000;
        stats.p99_us = sorted_samples[sorted_samples.size() * 99 / 100] / 1000;

        // Compute average
        uint64_t sum = 0;
        for (uint64_t sample : sorted_samples) {
            sum += sample;
        }
        stats.avg_us = static_cast<double>(sum) / sorted_samples.size() / 1000.0;

        return stats;
    }

private:
    static constexpr uint32_t BUFFER_SIZE = 10000;  // Last 10k samples
    std::array<uint64_t, BUFFER_SIZE> samples_;
    std::atomic<uint32_t> write_idx_;
};

// Production callback for market data
class MarketStreamCallback : public MarketDataCallbacks {
public:
    void on_trade(const MarketTick& tick) override {
        spdlog::debug("[TRADE] {}:{} @ ${:.2f} x {:.4f} {}",
                     tick.exchange.c_str(), tick.symbol.c_str(),
                     tick.price, tick.amount, tick.side.c_str());

        // Record latency (receipt to callback)
        auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        uint64_t latency_ns = now_ns - tick.timestamp_ns;
        trade_latency_.record(latency_ns);

        trade_count_++;
    }

    void on_orderbook(const OrderBookSnapshot& snapshot) override {
        spdlog::debug("[BOOK] {}:{} - Mid: ${:.2f} Spread: {:.2f} bps",
                     snapshot.exchange.c_str(), snapshot.symbol.c_str(),
                     snapshot.midpoint,
                     snapshot.relative_spread * 10000);

        // Record latency (receipt to callback)
        auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        uint64_t latency_ns = now_ns - snapshot.timestamp_ns;
        book_latency_.record(latency_ns);

        book_count_++;
    }

    void on_error(const std::string& error) override {
        spdlog::error("[ERROR] {}", error);
    }

    uint64_t get_trade_count() const { return trade_count_.load(); }
    uint64_t get_book_count() const { return book_count_.load(); }

    LatencyTracker::Stats get_trade_latency_stats() { return trade_latency_.compute_stats(); }
    LatencyTracker::Stats get_book_latency_stats() { return book_latency_.compute_stats(); }

private:
    std::atomic<uint64_t> trade_count_{0};
    std::atomic<uint64_t> book_count_{0};
    LatencyTracker trade_latency_;
    LatencyTracker book_latency_;
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
        int stats_interval = 150; // seconds (2.5 minutes)

        while (!g_shutdown.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(stats_interval));

            if (!g_shutdown.load()) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();

                // Compute latency statistics (done in background thread, not hot path)
                auto trade_stats = callbacks->get_trade_latency_stats();
                auto book_stats = callbacks->get_book_latency_stats();

                // Monitoring-friendly format: type=value pairs for easy parsing
                if (trade_stats.count > 0) {
                    spdlog::info("[LATENCY] stream=trade samples={} min_us={} p50_us={} p95_us={} p99_us={} max_us={} avg_us={:.1f} uptime_s={}",
                               trade_stats.count,
                               trade_stats.min_us,
                               trade_stats.p50_us,
                               trade_stats.p95_us,
                               trade_stats.p99_us,
                               trade_stats.max_us,
                               trade_stats.avg_us,
                               elapsed);
                }

                if (book_stats.count > 0) {
                    spdlog::info("[LATENCY] stream=book samples={} min_us={} p50_us={} p95_us={} p99_us={} max_us={} avg_us={:.1f} uptime_s={}",
                               book_stats.count,
                               book_stats.min_us,
                               book_stats.p50_us,
                               book_stats.p95_us,
                               book_stats.p99_us,
                               book_stats.max_us,
                               book_stats.avg_us,
                               elapsed);
                }

                // Overall throughput in monitoring format
                uint64_t total_trades = callbacks->get_trade_count();
                uint64_t total_books = callbacks->get_book_count();
                spdlog::info("[THROUGHPUT] trades_total={} trades_per_sec={:.1f} books_total={} books_per_sec={:.1f} uptime_s={}",
                           total_trades,
                           elapsed > 0 ? static_cast<double>(total_trades) / elapsed : 0.0,
                           total_books,
                           elapsed > 0 ? static_cast<double>(total_books) / elapsed : 0.0,
                           elapsed);
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
