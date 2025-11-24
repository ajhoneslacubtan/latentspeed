/**
 * @file market_data_provider.h
 * @brief Ultra-low latency market data provider with ZMQ publishing
 * @author jessiondiwangan@gmail.com
 * @date 2025
 * 
 * HFT-OPTIMIZED FEATURES:
 * - Lock-free market data processing
 * - Zero-copy ZMQ publishing to ports 5556 (trades) and 5557 (orderbook)
 * - 10-level orderbook depth with microsecond timestamps
 * - Memory pools for data structures to avoid allocations
 * - CPU affinity for dedicated market data threads
 */

#pragma once

#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <functional>
#include <map>
#include <unordered_map>
#include <vector>
#include <cstdint>
#include <string_view>
#include <chrono>
#include <mutex>

// ZeroMQ for market data publishing
#include <zmq.hpp>

// JSON processing
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

// WebSocket client using Boost.Beast
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>

// HFT data structures
#include "hft_data_structures.h"
#include "rolling_stats.h"
#include <spdlog/spdlog.h>

namespace latentspeed {

/**
 * @struct MarketTick
 * @brief HFT-optimized trade tick data structure
 */
struct MarketTick {
    uint64_t timestamp_ns;           ///< Nanosecond timestamp (receipt_timestamp_ns)
    hft::FixedString<32> symbol;     ///< Trading symbol (e.g., "BTCUSDT")
    hft::FixedString<16> exchange;   ///< Exchange name (e.g., "bybit")
    double price;                    ///< Trade price
    double amount;                   ///< Trade amount (renamed from quantity)
    hft::FixedString<8> side;        ///< Trade side: "buy" or "sell"
    hft::FixedString<64> trade_id;   ///< Exchange trade ID
    
    // Derived fields (computed from raw data)
    double transaction_price;        ///< Transaction price (= price for single fill)
    double trading_volume;           ///< Trading volume (price * amount)
    uint64_t seq;                    ///< Sequence number per stream
    
    // Rolling statistics
    double volatility_transaction_price;  ///< Rolling volatility of transaction price
    int window_size;                      ///< Window size used for stats
    
    MarketTick() : timestamp_ns(0), price(0.0), amount(0.0), 
                   transaction_price(0.0), trading_volume(0.0), seq(0),
                   volatility_transaction_price(0.0), window_size(20) {}
};

/**
 * @struct OrderBookLevel
 * @brief Single orderbook level (price/quantity pair)
 */
struct OrderBookLevel {
    double price;
    double quantity;
    
    OrderBookLevel() : price(0.0), quantity(0.0) {}
    OrderBookLevel(double p, double q) : price(p), quantity(q) {}
};

/**
 * @struct OrderBookSnapshot
 * @brief HFT-optimized L2 orderbook snapshot (10 levels each side)
 */
struct OrderBookSnapshot {
    uint64_t timestamp_ns;                    ///< Nanosecond timestamp (receipt_timestamp_ns)
    hft::FixedString<32> symbol;              ///< Trading symbol
    hft::FixedString<16> exchange;            ///< Exchange name
    std::array<OrderBookLevel, 10> bids;      ///< Bid levels (highest to lowest)
    std::array<OrderBookLevel, 10> asks;      ///< Ask levels (lowest to highest)
    uint64_t seq;                             ///< Sequence number per stream
    
    // Derived Level 1 features (computed from top of book)
    double midpoint;                          ///< (best_bid + best_ask) / 2
    double relative_spread;                   ///< (ask - bid) / mid
    double breadth;                           ///< bid_px*bid_sz + ask_px*ask_sz
    double imbalance_lvl1;                    ///< (bid_sz - ask_sz) / total
    
    // Derived depth features (sum across N levels)
    double bid_depth_n;                       ///< sum(price_i * size_i) for bids
    double ask_depth_n;                       ///< sum(price_i * size_i) for asks
    double depth_n;                           ///< total depth (bid + ask)
    
    // Rolling statistics
    double volatility_mid;                    ///< Rolling volatility of midpoint
    double ofi_rolling;                       ///< Rolling order flow imbalance
    int window_size;                          ///< Window size used for stats
    
    OrderBookSnapshot() : timestamp_ns(0), seq(0), midpoint(0.0), 
                         relative_spread(0.0), breadth(0.0), imbalance_lvl1(0.0),
                         bid_depth_n(0.0), ask_depth_n(0.0), depth_n(0.0),
                         volatility_mid(0.0), ofi_rolling(0.0), window_size(20) {}
};

/**
 * @brief WebSocket client configuration
 */
struct WSConfig {
    std::string url;
    std::vector<std::string> symbols;
    bool enable_trades = true;
    bool enable_orderbook = true;
    int orderbook_depth = 10;
};

/**
 * @brief Market data callbacks interface
 */
class MarketDataCallbacks {
public:
    virtual ~MarketDataCallbacks() = default;
    virtual void on_trade(const MarketTick& tick) = 0;
    virtual void on_orderbook(const OrderBookSnapshot& snapshot) = 0;
    virtual void on_error(const std::string& error) = 0;
};

/**
 * @class MarketDataProvider
 * @brief Ultra-low latency market data provider with ZMQ publishing
 * 
 * Features:
 * - Direct WebSocket connections to exchanges
 * - Lock-free data processing pipelines
 * - ZMQ publishing on separate ports for trades and orderbook
 * - Memory pools to avoid allocations in hot path
 * - Sub-microsecond processing latency targets
 */
// Forward declaration
class ExchangeInterface;

class MarketDataProvider {
public:
    /**
     * @brief Constructor
     * @param exchange Exchange name (e.g., "bybit", "binance")
     * @param symbols List of symbols to subscribe
     * @param exchange_interface Optional exchange interface (for multi-exchange support)
     * @param reconnect_attempts Max reconnection attempts (default: 10)
     * @param reconnect_delay_ms Delay between reconnection attempts (default: 5000ms)
     * @param subscription_delay_ms Delay between individual subscriptions for rate limiting (default: 100ms)
     */
    MarketDataProvider(const std::string& exchange,
                      const std::vector<std::string>& symbols,
                      ExchangeInterface* exchange_interface = nullptr,
                      int reconnect_attempts = 10,
                      int reconnect_delay_ms = 5000,
                      int subscription_delay_ms = 100);
    
    /**
     * @brief Destructor
     */
    ~MarketDataProvider();
    
    /**
     * @brief Initialize ZMQ publishers and WebSocket connections
     * @return true if initialization successful
     */
    bool initialize();
    
    /**
     * @brief Start market data streaming
     */
    void start();
    
    /**
     * @brief Stop market data streaming
     */
    void stop();
    
    /**
     * @brief Check if provider is running
     */
    bool is_running() const { return running_.load(std::memory_order_acquire); }
    
    /**
     * @brief Set market data callback handler
     */
    void set_callbacks(std::shared_ptr<MarketDataCallbacks> callbacks);
    
    /**
     * @brief Get current statistics
     */
    struct Stats {
        std::atomic<uint64_t> trades_processed{0};
        std::atomic<uint64_t> orderbooks_processed{0};
        std::atomic<uint64_t> messages_published{0};
        std::atomic<uint64_t> errors{0};
    };
    
    const Stats& get_stats() const { return stats_; }

    // Configure outputs (snapshot vs delta/ckpt) and related knobs
    void configure_outputs(bool emit_snapshot, bool emit_delta, bool emit_ckpt, int ckpt_every_ms, int depth_levels);

private:
    // Boost.Beast WebSocket type aliases
    using tcp = boost::asio::ip::tcp;
    using WSStream = boost::beast::websocket::stream<boost::beast::ssl_stream<boost::beast::tcp_stream>>;
    using WSBuffer = boost::beast::flat_buffer;
    
    /**
     * @brief WebSocket thread for handling connections
     */
    void websocket_thread();
    
    /**
     * @brief Data processing thread
     */
    void processing_thread();
    
    /**
     * @brief ZMQ publishing thread
     */
    void publishing_thread();
    
    /**
     * @brief WebSocket connection management
     * @return true if connection successful, false otherwise
     */
    bool connect_websocket();
    void handle_websocket_message(const std::string& message);
    void send_subscription();

    /**
     * @brief Async WebSocket read handler
     */
    void async_read_message();

    /**
     * @brief Send ping message to exchange
     */
    void send_ping();

    /**
     * @brief Setup ping timer for periodic pings
     */
    void setup_ping_timer();

    /**
     * @brief Cleanup WebSocket connection and related resources
     */
    void cleanup_connection();

    /**
     * @brief Calculate exponential backoff delay
     * @param attempt Current reconnection attempt number (0-based)
     * @param base_delay_ms Base delay in milliseconds
     * @return Delay in milliseconds with exponential backoff and jitter
     */
    uint32_t calculate_backoff_delay(uint32_t attempt, int base_delay_ms);
    
    /**
     * @brief Exchange-specific message parsing
     */
    void parse_bybit_message(const std::string& message);
    void parse_binance_message(const std::string& message);
    
    /**
     * @brief Parse trade data from JSON
     */
    bool parse_trade_data(const rapidjson::Value& doc, MarketTick& tick);
    
    /**
     * @brief Parse orderbook data from JSON
     */
    bool parse_orderbook_data(const rapidjson::Value& doc, OrderBookSnapshot& snapshot);
    
    /**
     * @brief Publish trade data to ZMQ port 5556
     */
    void publish_trade(const MarketTick& tick);
    
    /**
     * @brief Publish orderbook data to ZMQ port 5557
     */
    void publish_orderbook(const OrderBookSnapshot& snapshot);
    
    /**
     * @brief Serialize market tick to JSON
     */
    std::string serialize_trade(const MarketTick& tick);
    
    /**
     * @brief Serialize orderbook snapshot to JSON
     */
    std::string serialize_orderbook(const OrderBookSnapshot& snapshot);
    
    /**
     * @brief Get current timestamp in nanoseconds
     */
    uint64_t get_timestamp_ns();
    
    /**
     * @brief Build WebSocket subscription message
     */
    std::string build_subscription_message();

private:
    // Configuration
    std::string exchange_;
    std::vector<std::string> symbols_;
    std::atomic<bool> running_{false};
    ExchangeInterface* exchange_interface_;  ///< Exchange abstraction (optional)
    
    // Boost.Beast WebSocket components
    std::unique_ptr<boost::asio::io_context> io_context_;
    std::unique_ptr<boost::asio::ssl::context> ssl_context_;
    std::unique_ptr<WSStream> ws_stream_;
    std::unique_ptr<std::thread> ws_thread_;
    WSBuffer ws_buffer_;

    // Ping/pong management
    std::unique_ptr<boost::asio::steady_timer> ping_timer_;
    std::chrono::steady_clock::time_point last_message_time_;
    std::chrono::steady_clock::time_point last_ping_time_;
    std::mutex ping_mutex_;

    // Reconnection management
    std::atomic<bool> reconnecting_{false};
    std::atomic<uint32_t> reconnect_attempts_{0};
    std::atomic<bool> ws_connected_{false};
    int max_reconnect_attempts_{10};
    int reconnect_delay_ms_{5000};
    int subscription_delay_ms_{100};
    std::chrono::steady_clock::time_point last_reconnect_attempt_;
    
    // ZMQ components
    std::unique_ptr<zmq::context_t> zmq_context_;
    std::unique_ptr<zmq::socket_t> trades_publisher_;    // Port 5556
    std::unique_ptr<zmq::socket_t> orderbook_publisher_; // Port 5557
    
    // Processing threads
    std::unique_ptr<std::thread> processing_thread_;
    std::unique_ptr<std::thread> publishing_thread_;
    
    // Memory pools for zero-allocation processing
    std::unique_ptr<hft::MemoryPool<MarketTick, 1024>> tick_pool_;
    std::unique_ptr<hft::MemoryPool<OrderBookSnapshot, 512>> orderbook_pool_;
    
    // Lock-free queues for inter-thread communication
    std::unique_ptr<hft::LockFreeSPSCQueue<MarketTick, 4096>> tick_queue_;
    std::unique_ptr<hft::LockFreeSPSCQueue<OrderBookSnapshot, 2048>> orderbook_queue_;
    
    // Raw message queue from WebSocket
    // Fixed-size message buffer for lock-free queue (std::string is not trivially copyable)
    // Increased to 512KB to handle large orderbook snapshots from all exchanges
    using MessageBuffer = std::array<char, 524288>;
    std::unique_ptr<hft::LockFreeSPSCQueue<MessageBuffer, 4096>> message_queue_;
    
    // Callback handler
    std::shared_ptr<MarketDataCallbacks> callbacks_;
    
    // Statistics
    mutable Stats stats_;
    
    // Synchronization
    std::mutex connection_mutex_;
    
    // Sequence counters per stream (exchange:stream_type:symbol)
    std::unordered_map<std::string, uint64_t> sequence_counters_;
    std::mutex seq_mutex_;
    
    // Rolling statistics per symbol
    std::unordered_map<std::string, RollingStats> mid_stats_;      // For book midpoint volatility
    std::unordered_map<std::string, RollingStats> trade_stats_;    // For trade price volatility
    std::mutex stats_mutex_;

    // Output selection and state (delta/ckpt synthesis)
    bool emit_snapshot_ = true;
    bool emit_delta_ = false;
    bool emit_ckpt_ = false;
    int ckpt_every_ms_ = 1000;
    int depth_levels_cfg_ = 10;
    std::unordered_map<std::string, std::unordered_map<double,double>> last_bids_;
    std::unordered_map<std::string, std::unordered_map<double,double>> last_asks_;
    std::unordered_map<std::string, uint64_t> last_ckpt_ns_;

    // Symbol canonicalization: coin (e.g., BTC) -> configured canonical symbol (e.g., BTC-USDT-PERP)
    std::unordered_map<std::string, std::string> coin_to_canonical_;
    std::string canonicalize_symbol(const std::string& sym) const;
    static std::string _coin_from_canonical(const std::string& configured_symbol);
    
    /**
     * @brief Get next sequence number for a stream
     */
    uint64_t get_next_seq(const std::string& stream_key);
    
    /**
     * @brief Compute derived book features
     */
    void compute_book_features(OrderBookSnapshot& snapshot);
    
    /**
     * @brief Compute derived trade features
     */
    void compute_trade_features(MarketTick& tick);
    
    /**
     * @brief Normalize symbol (underscore to dash)
     */
    std::string normalize_symbol(const std::string& symbol);
    
    /**
     * @brief Check if topic is a heartbeat message
     */
    bool is_heartbeat(const std::string& topic);

    // New: emit deltas/checkpoints and (optionally) snapshots
    void emit_book_outputs(const OrderBookSnapshot& snapshot);
    std::string serialize_book_delta(
        const std::string& symbol,
        const std::string& exchange,
        const std::vector<int>& side,
        const std::vector<double>& px,
        const std::vector<double>& sz,
        uint64_t ts_ns,
        uint64_t seq
    );
    std::string serialize_book_ckpt(
        const std::string& symbol,
        const std::string& exchange,
        const std::vector<double>& bid_px,
        const std::vector<double>& bid_sz,
        const std::vector<double>& ask_px,
        const std::vector<double>& ask_sz,
        uint64_t ts_ns,
        uint64_t seq
    );
};

/**
 * @class SimpleMarketDataCallback
 * @brief Simple callback implementation for testing
 */
class SimpleMarketDataCallback : public MarketDataCallbacks {
public:
    void on_trade(const MarketTick& tick) override {
        spdlog::info("[MarketData] Trade: {} {} @ {} x {} ({})", 
                     tick.exchange.c_str(), tick.symbol.c_str(), 
                     tick.price, tick.amount, tick.side.c_str());
    }
    
    void on_orderbook(const OrderBookSnapshot& snapshot) override {
        spdlog::info("[MarketData] OrderBook: {} {} - Best bid: {:.4f} @ {:.4f}, Best ask: {:.4f} @ {:.4f}",
                     snapshot.exchange.c_str(), snapshot.symbol.c_str(),
                     snapshot.bids[0].price, snapshot.bids[0].quantity,
                     snapshot.asks[0].price, snapshot.asks[0].quantity);
    }
    
    void on_error(const std::string& error) override {
        spdlog::error("[MarketData] Error: {}", error);
    }
};

} // namespace latentspeed
