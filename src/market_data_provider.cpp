/**
 * @file market_data_provider.cpp
 * @brief Ultra-low latency market data provider implementation
 * @author jessiondiwangan@gmail.com
 * @date 2025
 */

#include "market_data_provider.h"
#include "exchange_interface.h"
#include <spdlog/spdlog.h>
#include <rapidjson/error/en.h>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <set>
#include <limits>
#include <random>

#ifdef __linux__
#include <pthread.h>
#include <sched.h>
#endif

namespace latentspeed {

MarketDataProvider::MarketDataProvider(const std::string& exchange,
                                     const std::vector<std::string>& symbols,
                                     ExchangeInterface* exchange_interface,
                                     int reconnect_attempts,
                                     int reconnect_delay_ms,
                                     int subscription_delay_ms)
    : exchange_(exchange)
    , symbols_(symbols)
    , running_(false)
    , exchange_interface_(exchange_interface)
    , max_reconnect_attempts_(reconnect_attempts)
    , reconnect_delay_ms_(reconnect_delay_ms)
    , subscription_delay_ms_(subscription_delay_ms) {

    spdlog::info("[MarketData] Initializing provider for exchange: {} (reconnect: {} attempts, {} ms delay, subscription: {} ms delay)",
                 exchange_, max_reconnect_attempts_, reconnect_delay_ms_, subscription_delay_ms_);
    
    // Initialize memory pools
    tick_pool_ = std::make_unique<hft::MemoryPool<MarketTick, 1024>>();
    orderbook_pool_ = std::make_unique<hft::MemoryPool<OrderBookSnapshot, 512>>();
    
    // Initialize lock-free queues
    tick_queue_ = std::make_unique<hft::LockFreeSPSCQueue<MarketTick, 4096>>();
    orderbook_queue_ = std::make_unique<hft::LockFreeSPSCQueue<OrderBookSnapshot, 2048>>();
    // Initialize raw message queue from WebSocket (256KB buffer, 4096 depth = ~1GB total)
    message_queue_ = std::make_unique<hft::LockFreeSPSCQueue<MessageBuffer, 4096>>();

    // Build coin -> canonical symbol mapping for topic alignment with consumers
    try {
        for (const auto& s : symbols_) {
            std::string canon = s; // as configured
            std::string coin = _coin_from_canonical(canon);
            if (!coin.empty()) {
                std::string upper = coin;
                std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
                coin_to_canonical_[upper] = canon; // e.g., BTC -> BTC-USDT-PERP
            }
        }
    } catch (const std::exception&) {
        // best-effort; proceed without mapping
    }

    spdlog::info("[MarketData] Memory pools and queues initialized");
}

MarketDataProvider::~MarketDataProvider() {
    stop();
}

bool MarketDataProvider::initialize() {
    try {
        spdlog::info("[MarketData] Initializing ZMQ context and publishers...");
        
        // Initialize ZMQ context
        zmq_context_ = std::make_unique<zmq::context_t>(1);
        
        // Initialize trades publisher (port 5556)
        trades_publisher_ = std::make_unique<zmq::socket_t>(*zmq_context_, ZMQ_PUB);
        trades_publisher_->set(zmq::sockopt::sndhwm, 1000);
        trades_publisher_->set(zmq::sockopt::sndtimeo, 0);
        trades_publisher_->bind("tcp://*:5556");
        
        // Initialize orderbook publisher (port 5557)
        orderbook_publisher_ = std::make_unique<zmq::socket_t>(*zmq_context_, ZMQ_PUB);
        orderbook_publisher_->set(zmq::sockopt::sndhwm, 1000);
        orderbook_publisher_->set(zmq::sockopt::sndtimeo, 0);
        orderbook_publisher_->bind("tcp://*:5557");
        
        // Initialize Boost.Beast WebSocket components
        io_context_ = std::make_unique<boost::asio::io_context>();
        ssl_context_ = std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv12_client);
        
        // Configure SSL context
        ssl_context_->set_default_verify_paths();
        ssl_context_->set_verify_mode(boost::asio::ssl::verify_peer);
        
        spdlog::info("[MarketData] ZMQ publishers bound to ports 5556 (trades) and 5557 (orderbook)");
        spdlog::info("[MarketData] WebSocket client initialized");
        
        return true;
    } catch (const std::exception& e) {
        spdlog::error("[MarketData] Initialization failed: {}", e.what());
        return false;
    }
}

void MarketDataProvider::start() {
    if (running_.exchange(true)) {
        spdlog::warn("[MarketData] Already running");
        return;
    }
    
    spdlog::info("[MarketData] Starting market data provider for {} symbols", symbols_.size());

    // Log subscribed symbols (first 5)
    {
        std::string symbols_str;
        for (size_t i = 0; i < std::min(symbols_.size(), size_t(5)); ++i) {
            if (i > 0) symbols_str += ", ";
            symbols_str += symbols_[i];
        }
        if (symbols_.size() > 5) {
            symbols_str += " (+" + std::to_string(symbols_.size() - 5) + " more)";
        }
        spdlog::info("[MarketData] Symbols: {}", symbols_str);
    }

    // Start WebSocket thread
    ws_thread_ = std::make_unique<std::thread>(&MarketDataProvider::websocket_thread, this);
    
    // Start processing thread
    processing_thread_ = std::make_unique<std::thread>(&MarketDataProvider::processing_thread, this);
    
    // Start publishing thread
    publishing_thread_ = std::make_unique<std::thread>(&MarketDataProvider::publishing_thread, this);
    
    // Set thread priorities and CPU affinity (Linux-specific)
#ifdef __linux__
    struct sched_param param;
    param.sched_priority = 50;
    
    // Set real-time priority for processing thread
    if (pthread_setschedparam(processing_thread_->native_handle(), SCHED_FIFO, &param) != 0) {
        spdlog::warn("[MarketData] Failed to set real-time scheduling for processing thread");
    }
    
    // CPU affinity
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(6, &cpuset); // Use CPU core 6 for WebSocket
    pthread_setaffinity_np(ws_thread_->native_handle(), sizeof(cpu_set_t), &cpuset);
    
    CPU_ZERO(&cpuset);
    CPU_SET(7, &cpuset); // Use CPU core 7 for processing
    pthread_setaffinity_np(processing_thread_->native_handle(), sizeof(cpu_set_t), &cpuset);
#endif
    
    spdlog::info("[MarketData] Market data provider started with {} symbols", symbols_.size());
}

void MarketDataProvider::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    
    spdlog::info("[MarketData] Stopping market data provider...");
    
    // Stop WebSocket connection
    if (ws_stream_) {
        try {
            ws_stream_->close(boost::beast::websocket::close_code::normal);
        } catch (const std::exception& e) {
            spdlog::warn("[MarketData] Error closing WebSocket: {}", e.what());
        }
    }
    
    if (io_context_) {
        io_context_->stop();
    }
    
    // Join threads
    if (ws_thread_ && ws_thread_->joinable()) {
        ws_thread_->join();
    }
    if (processing_thread_ && processing_thread_->joinable()) {
        processing_thread_->join();
    }
    if (publishing_thread_ && publishing_thread_->joinable()) {
        publishing_thread_->join();
    }
    
    spdlog::info("[MarketData] Market data provider stopped");
    spdlog::info("[MarketData] Final stats - Trades: {}, OrderBooks: {}, Published: {}, Errors: {}",
                 stats_.trades_processed.load(),
                 stats_.orderbooks_processed.load(),
                 stats_.messages_published.load(),
                 stats_.errors.load());
}

void MarketDataProvider::set_callbacks(std::shared_ptr<MarketDataCallbacks> callbacks) {
    callbacks_ = callbacks;
}

void MarketDataProvider::configure_outputs(bool emit_snapshot, bool emit_delta, bool emit_ckpt, int ckpt_every_ms, int depth_levels) {
    emit_snapshot_ = emit_snapshot;
    emit_delta_ = emit_delta;
    emit_ckpt_ = emit_ckpt;
    ckpt_every_ms_ = ckpt_every_ms;
    depth_levels_cfg_ = depth_levels;
    spdlog::info("[MarketData] Outputs configured: snapshot={}, delta={}, ckpt={}, ckpt_every_ms={}, depth_levels={}",
                 emit_snapshot_, emit_delta_, emit_ckpt_, ckpt_every_ms_, depth_levels_cfg_);
}

void MarketDataProvider::websocket_thread() {
    spdlog::info("[MarketData] WebSocket thread started");

    uint32_t backoff_attempt = 0;

    while (running_.load() && backoff_attempt <= max_reconnect_attempts_) {
        try {
            // Connect (TCP + SSL + WS handshake + subscribe)
            if (!connect_websocket()) {
                spdlog::warn("[MarketData] Connection failed, will retry...");
                goto retry_with_backoff;
            }

            // Reset reconnection state on successful connection
            if (backoff_attempt > 0) {
                spdlog::info("[MarketData] Successfully reconnected after {} attempt(s)", backoff_attempt);
            }
            backoff_attempt = 0;
            reconnect_attempts_.store(0);

            // Initialize ping timer if exchange requires pings
            if (exchange_interface_ && exchange_interface_->get_ping_interval_seconds() > 0) {
                ping_timer_ = std::make_unique<boost::asio::steady_timer>(*io_context_);
                last_message_time_ = std::chrono::steady_clock::now();
                last_ping_time_ = std::chrono::steady_clock::now();
                setup_ping_timer();
                spdlog::info("[MarketData] Ping timer initialized (interval: {}s)",
                            exchange_interface_->get_ping_interval_seconds());
            }

            // Start async read
            async_read_message();

            // Run the I/O context (blocks until error or stop)
            io_context_->run();

            // If we get here, connection was closed (expected or error)
            spdlog::info("[MarketData] io_context run() exited, cleaning up...");
            cleanup_connection();

        } catch (const std::exception& e) {
            spdlog::error("[MarketData] WebSocket thread error: {}", e.what());
            stats_.errors.fetch_add(1);
            if (callbacks_) {
                callbacks_->on_error("WebSocket error: " + std::string(e.what()));
            }
            cleanup_connection();
        }

    retry_with_backoff:
        // Check if we should stop
        if (!running_.load()) {
            spdlog::info("[MarketData] Shutting down, not reconnecting");
            break;
        }

        // Check if we've exceeded max attempts
        if (backoff_attempt >= max_reconnect_attempts_) {
            spdlog::error("[MarketData] Max reconnection attempts ({}) reached, giving up",
                         max_reconnect_attempts_);
            if (callbacks_) {
                callbacks_->on_error("Max reconnection attempts exceeded");
            }
            break;
        }

        // Calculate exponential backoff delay
        uint32_t delay_ms = calculate_backoff_delay(backoff_attempt, reconnect_delay_ms_);
        spdlog::info("[MarketData] Reconnecting in {} ms (attempt {}/{})",
                     delay_ms, backoff_attempt + 1, max_reconnect_attempts_);

        reconnect_attempts_.store(backoff_attempt + 1);
        last_reconnect_attempt_ = std::chrono::steady_clock::now();

        // Wait with periodic check for shutdown signal
        auto wait_until = std::chrono::steady_clock::now() + std::chrono::milliseconds(delay_ms);
        while (running_.load() && std::chrono::steady_clock::now() < wait_until) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (!running_.load()) {
            spdlog::info("[MarketData] Shutdown requested during backoff, exiting");
            break;
        }

        backoff_attempt++;
    }

    spdlog::info("[MarketData] WebSocket thread stopped");
}

bool MarketDataProvider::connect_websocket() {
    std::lock_guard<std::mutex> lock(connection_mutex_);

    spdlog::info("[MarketData] Starting WebSocket connection...");

    // Cleanup previous connection if exists
    if (ws_stream_) {
        spdlog::debug("[MarketData] Cleaning up previous WebSocket connection");
        try {
            if (ws_stream_->is_open()) {
                ws_stream_->close(boost::beast::websocket::close_code::normal);
            }
        } catch (const std::exception& e) {
            spdlog::debug("[MarketData] Error closing previous connection: {}", e.what());
        }
        ws_stream_.reset();
    }

    // Ensure ws_stream_ is fully reset
    ws_stream_ = nullptr;

    // Reset io_context if stopped
    if (io_context_ && io_context_->stopped()) {
        spdlog::debug("[MarketData] Restarting stopped io_context");
        io_context_->restart();
    }

    std::string host, port, target;

    try {
    
    // Use exchange interface if available, otherwise fallback to hardcoded
    if (exchange_interface_) {
        host = exchange_interface_->get_websocket_host();
        port = exchange_interface_->get_websocket_port();
        target = exchange_interface_->get_websocket_target();
    } else {
        // Fallback: Exchange-specific WebSocket URLs
        if (exchange_ == "bybit") {
            host = "stream.bybit.com";
            port = "443";
            target = "/v5/public/spot";
        } else if (exchange_ == "binance") {
            host = "stream.binance.com";
            port = "9443";
            target = "/ws";
        } else {
            throw std::runtime_error("Unsupported exchange: " + exchange_);
        }
    }
    
    spdlog::info("[MarketData] Connecting to WebSocket: wss://{}:{}{}", host, port, target);
    
    // Create WebSocket stream
    ws_stream_ = std::make_unique<WSStream>(*io_context_, *ssl_context_);
    
    // Set SNI Hostname
    if (!SSL_set_tlsext_host_name(ws_stream_->next_layer().native_handle(), host.c_str())) {
        throw std::runtime_error("Failed to set SNI hostname");
    }
    
    // Resolve hostname
    boost::asio::ip::tcp::resolver resolver(*io_context_);
    auto const results = resolver.resolve(host, port);
    
    // Connect to server
    auto ep = boost::beast::get_lowest_layer(*ws_stream_).connect(results);
    
    // Update the host string for HTTP/1.1 header
    host += ":" + std::to_string(ep.port());
    
    // Perform SSL handshake
    ws_stream_->next_layer().handshake(boost::asio::ssl::stream_base::client);
    
    // Set WebSocket options
    ws_stream_->set_option(boost::beast::websocket::stream_base::timeout::suggested(boost::beast::role_type::client));
    ws_stream_->set_option(boost::beast::websocket::stream_base::decorator([](boost::beast::websocket::request_type& req) {
        req.set(boost::beast::http::field::user_agent, "Latentspeed/1.0");
    }));
    
    // Perform WebSocket handshake
    spdlog::info("[MarketData] Performing WebSocket handshake...");
    ws_stream_->handshake(host, target);
    spdlog::info("[MarketData] WebSocket handshake completed");
    
    // Send subscription
    spdlog::info("[MarketData] Sending subscription message...");
    send_subscription();
    spdlog::info("[MarketData] WebSocket connection established, ready for async reads");

    ws_connected_.store(true);
    return true;

    } catch (const std::exception& e) {
        spdlog::error("[MarketData] WebSocket connection failed: {}", e.what());
        stats_.errors.fetch_add(1);
        ws_connected_.store(false);

        // Clean up failed connection to prevent segfaults
        if (ws_stream_) {
            try {
                if (ws_stream_->is_open()) {
                    ws_stream_->close(boost::beast::websocket::close_code::abnormal);
                }
            } catch (...) {
                // Ignore close errors on already-failed connection
            }
            ws_stream_.reset();
        }

        return false;
    }
}

void MarketDataProvider::cleanup_connection() {
    spdlog::info("[MarketData] Cleaning up WebSocket connection");

    ws_connected_.store(false);

    // Stop io_context first to prevent new async operations
    if (io_context_ && !io_context_->stopped()) {
        io_context_->stop();
    }

    // Give a brief moment for any in-flight async operations to complete
    // This prevents segfaults from callbacks trying to access resources we're about to destroy
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Cancel ping timer after io_context is stopped
    if (ping_timer_) {
        try {
            ping_timer_->cancel();
        } catch (const std::exception& e) {
            spdlog::debug("[MarketData] Error canceling ping timer: {}", e.what());
        }
        ping_timer_.reset();
    }

    // Close WebSocket gracefully - must hold mutex to prevent race with connect_websocket()
    {
        std::lock_guard<std::mutex> lock(connection_mutex_);
        if (ws_stream_) {
            try {
                if (ws_stream_->is_open()) {
                    ws_stream_->close(boost::beast::websocket::close_code::normal);
                }
            } catch (const std::exception& e) {
                spdlog::debug("[MarketData] Error closing WebSocket: {}", e.what());
            }
            ws_stream_.reset();
            ws_stream_ = nullptr;
        }
    }

    spdlog::debug("[MarketData] Connection cleanup complete");
}

uint32_t MarketDataProvider::calculate_backoff_delay(uint32_t attempt, int base_delay_ms) {
    // Exponential backoff: base_delay * 2^attempt, capped at 120 seconds
    constexpr uint32_t MAX_DELAY_MS = 120000;  // 2 minutes max

    uint32_t delay_ms = base_delay_ms * (1 << std::min(attempt, 5u));  // Cap exponent at 2^5 = 32
    delay_ms = std::min(delay_ms, MAX_DELAY_MS);

    // Add jitter (±10%) to prevent thundering herd
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> jitter(-delay_ms / 10, delay_ms / 10);

    delay_ms += jitter(gen);

    return delay_ms;
}

void MarketDataProvider::async_read_message() {
    if (!running_.load()) {
        return;
    }

    // Lock mutex to safely check and use ws_stream_
    std::lock_guard<std::mutex> lock(connection_mutex_);

    // Check if ws_stream_ is valid before attempting async read
    if (!ws_stream_ || !ws_stream_->is_open()) {
        spdlog::debug("[MarketData] async_read_message called with invalid ws_stream_, skipping");
        return;
    }

    ws_buffer_.clear();
    ws_stream_->async_read(
        ws_buffer_,
        [this](boost::beast::error_code ec, std::size_t bytes_transferred) {
            if (ec) {
                if (ec != boost::beast::websocket::error::closed) {
                    spdlog::error("[MarketData] WebSocket async_read error: {}", ec.message());
                    stats_.errors.fetch_add(1);
                    if (callbacks_) {
                        callbacks_->on_error("WebSocket error: " + ec.message());
                    }
                }
                // Stop io_context on error
                io_context_->stop();
                return;
            }

            // Update last message time
            {
                std::lock_guard<std::mutex> lock(ping_mutex_);
                last_message_time_ = std::chrono::steady_clock::now();
            }

            // Process received message
            std::string message = boost::beast::buffers_to_string(ws_buffer_.data());
            spdlog::trace("[MarketData] Received message ({} bytes): {}",
                         bytes_transferred, message.substr(0, 200));

            // Check if this is a pong response
            if (exchange_interface_ && exchange_interface_->is_pong_message(message)) {
                spdlog::trace("[MarketData] Received pong from {}", exchange_interface_->get_name());
                // Continue reading
                async_read_message();
                return;
            }

            // Skip heartbeat messages early to save processing
            if (message.find("-heartbeat") != std::string::npos ||
                message.find("heartbeat") != std::string::npos) {
                spdlog::trace("[MarketData] Skipping heartbeat message");
                async_read_message();
                return;
            }

            // Copy message to fixed-size buffer for lock-free queue
            MessageBuffer msg_buffer;
            size_t copy_size = std::min(message.size(), msg_buffer.size() - 1);

            // Warn if message is truncated
            if (message.size() >= msg_buffer.size()) {
                spdlog::warn("[MarketData] Message too large ({} bytes), truncating to {} bytes",
                           message.size(), msg_buffer.size() - 1);
            }

            std::memcpy(msg_buffer.data(), message.c_str(), copy_size);
            msg_buffer[copy_size] = '\0';

            // Push to processing queue
            if (!message_queue_->try_push(msg_buffer)) {
                spdlog::warn("[MarketData] Message queue full, dropping message");
                stats_.errors.fetch_add(1);
            }

            // Continue reading
            async_read_message();
        }
    );
}

void MarketDataProvider::send_ping() {
    if (!exchange_interface_ || !running_.load()) {
        return;
    }

    std::string ping_msg = exchange_interface_->generate_ping();
    if (ping_msg.empty()) {
        return;
    }

    // Lock mutex to safely check and use ws_stream_
    std::lock_guard<std::mutex> lock(connection_mutex_);

    // Check if ws_stream_ is valid before sending ping
    if (!ws_stream_ || !ws_stream_->is_open()) {
        spdlog::debug("[MarketData] Cannot send ping, WebSocket not connected");
        return;
    }

    try {
        ws_stream_->write(boost::asio::buffer(ping_msg));

        {
            std::lock_guard<std::mutex> lock2(ping_mutex_);
            last_ping_time_ = std::chrono::steady_clock::now();
        }

        spdlog::trace("[MarketData] Sent ping to {}", exchange_interface_->get_name());
    } catch (const std::exception& e) {
        spdlog::warn("[MarketData] Failed to send ping: {}", e.what());
        stats_.errors.fetch_add(1);
    }
}

void MarketDataProvider::setup_ping_timer() {
    if (!ping_timer_ || !exchange_interface_ || !running_.load()) {
        return;
    }

    int ping_interval = exchange_interface_->get_ping_interval_seconds();
    if (ping_interval <= 0) {
        return;
    }

    ping_timer_->expires_after(std::chrono::seconds(ping_interval));
    ping_timer_->async_wait(
        [this, ping_interval](boost::beast::error_code ec) {
            // If operation was cancelled, just return without doing anything
            if (ec == boost::asio::error::operation_aborted) {
                return;
            }

            if (ec || !running_.load()) {
                return;
            }

            // Send ping
            send_ping();

            // Check for stale connection (no messages received in 3x ping interval)
            bool should_stop = false;
            {
                std::lock_guard<std::mutex> lock(ping_mutex_);
                auto now = std::chrono::steady_clock::now();
                auto elapsed_since_msg = std::chrono::duration_cast<std::chrono::seconds>(
                    now - last_message_time_).count();

                if (elapsed_since_msg > (ping_interval * 3)) {
                    spdlog::warn("[MarketData] No messages received for {} seconds, triggering reconnect",
                               elapsed_since_msg);
                    stats_.errors.fetch_add(1);
                    if (callbacks_) {
                        callbacks_->on_error("Stale connection detected, reconnecting...");
                    }
                    should_stop = true;
                }
            }

            // Stop io_context AFTER releasing the lock and AFTER this callback completes
            // This prevents cleanup from running while we're still in this callback
            if (should_stop) {
                if (io_context_ && !io_context_->stopped()) {
                    io_context_->stop();
                }
                return;  // Don't reschedule timer
            }

            // Reschedule timer only if not stopping
            if (running_.load()) {
                setup_ping_timer();
            }
        }
    );
}

void MarketDataProvider::processing_thread() {
    spdlog::info("[MarketData] Processing thread started");
    
    MessageBuffer message;
    
    while (running_.load(std::memory_order_acquire)) {
        try {
            if (message_queue_->try_pop(message)) {
                // Convert buffer back to string
                std::string message_str(message.data());
                message_str = message_str.substr(0, message_str.find('\0')); // Remove null terminators
                
                // Parse message using exchange interface if available
                if (exchange_interface_) {
                    MarketTick tick;
                    OrderBookSnapshot snapshot;
                    
                    auto msg_type = exchange_interface_->parse_message(message_str, tick, snapshot);

                    // Log message type for debugging
                    spdlog::trace("[MarketData] Parsed message type: {} (msg: {})",
                                 static_cast<int>(msg_type), message_str.substr(0, 100));
                    
                    if (msg_type == ExchangeInterface::MessageType::TRADE) {
                        // Canonicalize symbol if we have a mapping (e.g., BTC -> BTC-USDT-PERP)
                        try {
                            std::string s = std::string(tick.symbol.c_str());
                            std::string cs = canonicalize_symbol(s);
                            if (!cs.empty() && cs != s) {
                                tick.symbol.assign(cs.c_str());
                            }
                        } catch (const std::exception&) {}
                        // Compute derived features
                        compute_trade_features(tick);
                        
                        // Get sequence number
                        std::string stream_key = std::string(tick.exchange.c_str()) + ":trade:" + 
                                                std::string(tick.symbol.c_str());
                        tick.seq = get_next_seq(stream_key);
                        
                        // Push to queue
                        if (!tick_queue_->try_push(tick)) {
                            spdlog::warn("[MarketData] Trade queue full");
                        }
                        stats_.trades_processed.fetch_add(1);
                    } 
                    else if (msg_type == ExchangeInterface::MessageType::BOOK) {
                        // Canonicalize symbol
                        try {
                            std::string s = std::string(snapshot.symbol.c_str());
                            std::string cs = canonicalize_symbol(s);
                            if (!cs.empty() && cs != s) {
                                snapshot.symbol.assign(cs.c_str());
                            }
                        } catch (const std::exception&) {}
                        // Compute derived features
                        compute_book_features(snapshot);
                        
                        // Get sequence number
                        std::string stream_key = std::string(snapshot.exchange.c_str()) + ":book:" + 
                                                std::string(snapshot.symbol.c_str());
                        snapshot.seq = get_next_seq(stream_key);
                        
                        // Push to queue
                        if (!orderbook_queue_->try_push(snapshot)) {
                            spdlog::warn("[MarketData] Orderbook queue full");
                        }
                        stats_.orderbooks_processed.fetch_add(1);
                    }
                    else if (msg_type == ExchangeInterface::MessageType::HEARTBEAT) {
                        spdlog::trace("[MarketData] Received heartbeat/subscription message");
                    }
                    else if (msg_type == ExchangeInterface::MessageType::UNKNOWN) {
                        spdlog::debug("[MarketData] Unknown message type: {}", message_str.substr(0, 200));
                    }
                    else if (msg_type == ExchangeInterface::MessageType::ERROR) {
                        spdlog::error("[MarketData] Error parsing message: {}", message_str.substr(0, 200));
                    }
                } else {
                    // Fallback: Parse message based on exchange
                    if (exchange_ == "bybit") {
                        parse_bybit_message(message_str);
                    } else if (exchange_ == "binance") {
                        parse_binance_message(message_str);
                    }
                }
            } else {
                std::this_thread::sleep_for(std::chrono::microseconds(10));
            }
        } catch (const std::exception& e) {
            spdlog::error("[MarketData] Processing error: {}", e.what());
            stats_.errors.fetch_add(1);
            if (callbacks_) {
                callbacks_->on_error("Processing error: " + std::string(e.what()));
            }
        }
    }
    
    spdlog::info("[MarketData] Processing thread stopped");
}

void MarketDataProvider::publishing_thread() {
    spdlog::info("[MarketData] Publishing thread started");
    
    MarketTick tick;
    OrderBookSnapshot snapshot;
    
    while (running_.load(std::memory_order_acquire)) {
        try {
            // Process trade ticks
            if (tick_queue_->try_pop(tick)) {
                publish_trade(tick);
                if (callbacks_) {
                    callbacks_->on_trade(tick);
                }
            }
            
            // Process orderbook snapshots (emit delta/ckpt and optionally snapshot)
            if (orderbook_queue_->try_pop(snapshot)) {
                emit_book_outputs(snapshot);
                if (emit_snapshot_) {
                    publish_orderbook(snapshot);
                }
                if (callbacks_) {
                    callbacks_->on_orderbook(snapshot);
                }
            }
            
            // Small yield if no data
            if (tick_queue_->empty() && orderbook_queue_->empty()) {
                std::this_thread::yield();
            }
        } catch (const std::exception& e) {
            spdlog::error("[MarketData] Publishing error: {}", e.what());
            stats_.errors.fetch_add(1);
        }
    }
    
    spdlog::info("[MarketData] Publishing thread stopped");
}

void MarketDataProvider::send_subscription() {
    std::string sub_msg = build_subscription_message();

    spdlog::debug("[MarketData] Subscription message: {}", sub_msg);

    try {
        // For dYdX and Hyperliquid, the subscription message is a JSON array of individual subscriptions
        // We need to send each one separately
        if (exchange_interface_ &&
            (exchange_interface_->get_name() == "DYDX" || exchange_interface_->get_name() == "HYPERLIQUID")) {
            rapidjson::Document doc;
            doc.Parse(sub_msg.c_str());

            if (doc.IsArray()) {
                size_t total_subs = doc.GetArray().Size();

                // Warn about large subscription counts
                if (total_subs > 50) {
                    spdlog::warn("[MarketData] Subscribing to {} channels - this may take {}+ seconds due to rate limits",
                                total_subs, (total_subs * subscription_delay_ms_) / 1000);
                }

                size_t count = 0;
                size_t failed_count = 0;
                for (auto& sub : doc.GetArray()) {
                    try {
                        rapidjson::StringBuffer buffer;
                        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                        sub.Accept(writer);

                        std::string individual_sub = buffer.GetString();

                        // Check if connection is still alive before writing
                        if (!ws_stream_ || !ws_stream_->is_open()) {
                            throw std::runtime_error("WebSocket connection lost during subscription");
                        }

                        size_t bytes = ws_stream_->write(boost::asio::buffer(individual_sub));

                        count++;
                        if (count % 20 == 0 || count == total_subs) {
                            spdlog::info("[MarketData] Subscription progress: {}/{}", count, total_subs);
                        }

                        spdlog::debug("[MarketData] Sent {} subscription ({} bytes): {}",
                                    exchange_interface_->get_name(), bytes, individual_sub);

                        // Configurable delay between subscriptions to avoid rate limiting
                        std::this_thread::sleep_for(std::chrono::milliseconds(subscription_delay_ms_));

                    } catch (const std::exception& e) {
                        failed_count++;
                        spdlog::warn("[MarketData] Failed to send subscription {}/{}: {}", count + 1, total_subs, e.what());

                        // If we've sent at least some subscriptions, consider it partial success
                        // Let the reconnection logic handle re-establishing the full connection
                        if (count >= 5) {
                            spdlog::warn("[MarketData] Sent {}/{} subscriptions before failure, will reconnect", count, total_subs);
                            throw;  // Trigger reconnection
                        } else {
                            // Failed early, likely connection issue from the start
                            throw;
                        }
                    }
                }

                if (failed_count > 0) {
                    spdlog::warn("[MarketData] Completed with {} failures out of {} subscriptions", failed_count, total_subs);
                } else {
                    spdlog::info("[MarketData] All {} subscriptions sent successfully", exchange_interface_->get_name());
                }
                return;
            }
        }

        // Standard single-message subscription (Bybit, Binance)
        if (!ws_stream_ || !ws_stream_->is_open()) {
            throw std::runtime_error("WebSocket connection lost before subscription");
        }

        size_t bytes_written = ws_stream_->write(boost::asio::buffer(sub_msg));
        spdlog::info("[MarketData] Subscription sent successfully ({} bytes)", bytes_written);
    } catch (const std::exception& e) {
        spdlog::error("[MarketData] Failed to send subscription: {}", e.what());

        // Mark connection as failed so cleanup knows the state
        ws_connected_.store(false);
        throw;
    }
}

void MarketDataProvider::handle_websocket_message(const std::string& message) {
    // Push to processing queue (this method is now replaced by inline code in connect_websocket)
    // Keeping for compatibility with other parts of the codebase
}

void MarketDataProvider::parse_bybit_message(const std::string& message) {
    try {
        rapidjson::Document doc;
        doc.Parse(message.c_str());
        
        if (doc.HasParseError()) {
            spdlog::warn("[MarketData] JSON parse error: {}", rapidjson::GetParseError_En(doc.GetParseError()));
            return;
        }
        
        // Check for topic field to determine message type
        if (!doc.HasMember("topic") || !doc["topic"].IsString()) {
            return; // Skip non-data messages
        }
        
        std::string topic = doc["topic"].GetString();
        
        // Parse trade data
        if (topic.find("publicTrade") != std::string::npos) {
            if (doc.HasMember("data") && doc["data"].IsArray()) {
                for (const auto& trade_data : doc["data"].GetArray()) {
                    MarketTick tick;
                    if (parse_trade_data(trade_data, tick)) {
                        if (!tick_queue_->try_push(tick)) {
                            spdlog::warn("[MarketData] Tick queue full");
                        } else {
                            stats_.trades_processed.fetch_add(1);
                        }
                    }
                }
            }
        }
        // Parse orderbook data
        else if (topic.find("orderbook") != std::string::npos) {
            if (doc.HasMember("data")) {
                OrderBookSnapshot snapshot;
                if (parse_orderbook_data(doc["data"], snapshot)) {
                    if (!orderbook_queue_->try_push(snapshot)) {
                        spdlog::warn("[MarketData] OrderBook queue full");
                    } else {
                        stats_.orderbooks_processed.fetch_add(1);
                    }
                }
            }
        }
        
    } catch (const std::exception& e) {
        spdlog::error("[MarketData] Bybit parse error: {}", e.what());
        stats_.errors.fetch_add(1);
    }
}

void MarketDataProvider::parse_binance_message(const std::string& message) {
    try {
        rapidjson::Document doc;
        doc.Parse(message.c_str());
        
        if (doc.HasParseError()) {
            spdlog::warn("[MarketData] JSON parse error: {}", rapidjson::GetParseError_En(doc.GetParseError()));
            return;
        }
        
        // Binance trade stream format
        if (doc.HasMember("e") && doc["e"].IsString()) {
            std::string event_type = doc["e"].GetString();
            
            if (event_type == "trade") {
                MarketTick tick;
                if (parse_trade_data(doc, tick)) {
                    if (!tick_queue_->try_push(tick)) {
                        spdlog::warn("[MarketData] Tick queue full");
                    } else {
                        stats_.trades_processed.fetch_add(1);
                    }
                }
            } else if (event_type == "depthUpdate") {
                OrderBookSnapshot snapshot;
                if (parse_orderbook_data(doc, snapshot)) {
                    if (!orderbook_queue_->try_push(snapshot)) {
                        spdlog::warn("[MarketData] OrderBook queue full");
                    } else {
                        stats_.orderbooks_processed.fetch_add(1);
                    }
                }
            }
        }
        
    } catch (const std::exception& e) {
        spdlog::error("[MarketData] Binance parse error: {}", e.what());
        stats_.errors.fetch_add(1);
    }
}

bool MarketDataProvider::parse_trade_data(const rapidjson::Value& doc, MarketTick& tick) {
    try {
        tick.timestamp_ns = get_timestamp_ns();
        tick.exchange.assign(exchange_);
        
        if (exchange_ == "bybit") {
            // Bybit trade format
            if (doc.HasMember("S") && doc["S"].IsString()) {
                tick.symbol.assign(normalize_symbol(doc["S"].GetString()));
            }
            if (doc.HasMember("p") && doc["p"].IsString()) {
                tick.price = std::stod(doc["p"].GetString());
            }
            if (doc.HasMember("v") && doc["v"].IsString()) {
                tick.amount = std::stod(doc["v"].GetString());
            }
            if (doc.HasMember("S") && doc["S"].IsString()) {
                tick.side.assign(doc["S"].GetString());
            }
            if (doc.HasMember("i") && doc["i"].IsString()) {
                tick.trade_id.assign(doc["i"].GetString());
            }
        } else if (exchange_ == "binance") {
            // Binance trade format
            if (doc.HasMember("s") && doc["s"].IsString()) {
                tick.symbol.assign(normalize_symbol(doc["s"].GetString()));
            }
            if (doc.HasMember("p") && doc["p"].IsString()) {
                tick.price = std::stod(doc["p"].GetString());
            }
            if (doc.HasMember("q") && doc["q"].IsString()) {
                tick.amount = std::stod(doc["q"].GetString());
            }
            if (doc.HasMember("m") && doc["m"].IsBool()) {
                tick.side.assign(doc["m"].GetBool() ? "sell" : "buy");
            }
            if (doc.HasMember("t") && doc["t"].IsUint64()) {
                tick.trade_id.assign(std::to_string(doc["t"].GetUint64()));
            }
        }
        
        if (!tick.symbol.empty() && tick.price > 0 && tick.amount > 0) {
            // Compute derived features
            compute_trade_features(tick);
            
            // Assign sequence number
            std::string seq_key = std::string(tick.exchange.c_str()) + ":preprocessed_trades:" + std::string(tick.symbol.c_str());
            tick.seq = get_next_seq(seq_key);
            
            return true;
        }
        
        return false;
        
    } catch (const std::exception& e) {
        spdlog::warn("[MarketData] Trade parse error: {}", e.what());
        return false;
    }
}

bool MarketDataProvider::parse_orderbook_data(const rapidjson::Value& doc, OrderBookSnapshot& snapshot) {
    try {
        snapshot.timestamp_ns = get_timestamp_ns();
        snapshot.exchange.assign(exchange_);
        
        if (exchange_ == "bybit") {
            // Bybit orderbook format
            if (doc.HasMember("s") && doc["s"].IsString()) {
                snapshot.symbol.assign(normalize_symbol(doc["s"].GetString()));
            }
            
            // Parse bids
            if (doc.HasMember("b") && doc["b"].IsArray()) {
                const auto& bids = doc["b"].GetArray();
                size_t count = std::min(static_cast<size_t>(bids.Size()), static_cast<size_t>(10));
                for (size_t i = 0; i < count; ++i) {
                    if (bids[i].IsArray() && bids[i].GetArray().Size() >= 2) {
                        const auto& level = bids[i].GetArray();
                        snapshot.bids[i].price = std::stod(level[0].GetString());
                        snapshot.bids[i].quantity = std::stod(level[1].GetString());
                    }
                }
            }
            
            // Parse asks
            if (doc.HasMember("a") && doc["a"].IsArray()) {
                const auto& asks = doc["a"].GetArray();
                size_t count = std::min(static_cast<size_t>(asks.Size()), static_cast<size_t>(10));
                for (size_t i = 0; i < count; ++i) {
                    if (asks[i].IsArray() && asks[i].GetArray().Size() >= 2) {
                        const auto& level = asks[i].GetArray();
                        snapshot.asks[i].price = std::stod(level[0].GetString());
                        snapshot.asks[i].quantity = std::stod(level[1].GetString());
                    }
                }
            }
        }
        
        if (!snapshot.symbol.empty() && snapshot.bids[0].price > 0 && snapshot.asks[0].price > 0) {
            // Compute derived features
            compute_book_features(snapshot);
            
            // Assign sequence number
            std::string seq_key = std::string(snapshot.exchange.c_str()) + ":preprocessed_book:" + std::string(snapshot.symbol.c_str());
            snapshot.seq = get_next_seq(seq_key);
            
            return true;
        }
        
        return false;
        
    } catch (const std::exception& e) {
        spdlog::warn("[MarketData] OrderBook parse error: {}", e.what());
        return false;
    }
}

void MarketDataProvider::publish_trade(const MarketTick& tick) {
    try {
        std::string json_data = serialize_trade(tick);
        
        // Create topic in format: "{EXCHANGE}-preprocessed_trades-{SYMBOL}"
        std::string topic = std::string(tick.exchange.c_str()) + "-preprocessed_trades-" + std::string(tick.symbol.c_str());
        
        // Create ZMQ message
        zmq::message_t topic_msg(topic.size());
        std::memcpy(topic_msg.data(), topic.c_str(), topic.size());
        
        zmq::message_t data_msg(json_data.size());
        std::memcpy(data_msg.data(), json_data.c_str(), json_data.size());
        
        // Publish to trades port (5556)
        if (trades_publisher_->send(topic_msg, zmq::send_flags::sndmore | zmq::send_flags::dontwait) &&
            trades_publisher_->send(data_msg, zmq::send_flags::dontwait)) {
            stats_.messages_published.fetch_add(1);
        }
        
    } catch (const std::exception& e) {
        spdlog::warn("[MarketData] Trade publish error: {}", e.what());
        stats_.errors.fetch_add(1);
    }
}

void MarketDataProvider::publish_orderbook(const OrderBookSnapshot& snapshot) {
    try {
        std::string json_data = serialize_orderbook(snapshot);
        
        // Create topic in format: "{EXCHANGE}-preprocessed_book-{SYMBOL}"
        std::string topic = std::string(snapshot.exchange.c_str()) + "-preprocessed_book-" + std::string(snapshot.symbol.c_str());
        
        // Create ZMQ message
        zmq::message_t topic_msg(topic.size());
        std::memcpy(topic_msg.data(), topic.c_str(), topic.size());
        
        zmq::message_t data_msg(json_data.size());
        std::memcpy(data_msg.data(), json_data.c_str(), json_data.size());
        
        // Publish to orderbook port (5557)
        if (orderbook_publisher_->send(topic_msg, zmq::send_flags::sndmore | zmq::send_flags::dontwait) &&
            orderbook_publisher_->send(data_msg, zmq::send_flags::dontwait)) {
            stats_.messages_published.fetch_add(1);
        }
        
    } catch (const std::exception& e) {
        spdlog::warn("[MarketData] OrderBook publish error: {}", e.what());
        stats_.errors.fetch_add(1);
    }
}

std::string MarketDataProvider::serialize_trade(const MarketTick& tick) {
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    
    writer.StartObject();
    
    // Core fields (matching Python schema)
    writer.Key("receipt_timestamp_ns"); writer.Uint64(tick.timestamp_ns);
    writer.Key("symbol"); writer.String(tick.symbol.c_str());
    writer.Key("exchange"); writer.String(tick.exchange.c_str());
    writer.Key("price"); writer.Double(tick.price);
    writer.Key("amount"); writer.Double(tick.amount);  // renamed from quantity
    writer.Key("side"); writer.String(tick.side.c_str());
    writer.Key("trade_id"); writer.String(tick.trade_id.c_str());
    
    // Derived features
    writer.Key("transaction_price"); writer.Double(tick.transaction_price);
    writer.Key("trading_volume"); writer.Double(tick.trading_volume);
    
    // Rolling statistics
    writer.Key("volatility_transaction_price"); writer.Double(tick.volatility_transaction_price);
    writer.Key("window_size"); writer.Int(tick.window_size);
    
    // Metadata
    writer.Key("seq"); writer.Uint64(tick.seq);
    writer.Key("schema_version"); writer.Int(1);
    
    // Preprocessing timestamp (ISO format)
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
    writer.Key("preprocessing_timestamp"); writer.String(ss.str().c_str());
    
    writer.EndObject();
    
    return buffer.GetString();
}

std::string MarketDataProvider::serialize_orderbook(const OrderBookSnapshot& snapshot) {
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    
    writer.StartObject();
    
    // Core fields (matching Python schema)
    writer.Key("receipt_timestamp_ns"); writer.Uint64(snapshot.timestamp_ns);
    writer.Key("symbol"); writer.String(snapshot.symbol.c_str());
    writer.Key("exchange"); writer.String(snapshot.exchange.c_str());
    writer.Key("seq"); writer.Uint64(snapshot.seq);
    
    // Top of book (Level 1)
    writer.Key("best_bid_price"); writer.Double(snapshot.bids[0].price);
    writer.Key("best_bid_size"); writer.Double(snapshot.bids[0].quantity);
    writer.Key("best_ask_price"); writer.Double(snapshot.asks[0].price);
    writer.Key("best_ask_size"); writer.Double(snapshot.asks[0].quantity);
    
    // Derived L1 features
    writer.Key("midpoint"); writer.Double(snapshot.midpoint);
    writer.Key("relative_spread"); writer.Double(snapshot.relative_spread);
    writer.Key("breadth"); writer.Double(snapshot.breadth);
    writer.Key("imbalance_lvl1"); writer.Double(snapshot.imbalance_lvl1);
    
    // Derived depth features
    writer.Key("bid_depth_n"); writer.Double(snapshot.bid_depth_n);
    writer.Key("ask_depth_n"); writer.Double(snapshot.ask_depth_n);
    writer.Key("depth_n"); writer.Double(snapshot.depth_n);
    
    // Rolling statistics
    writer.Key("volatility_mid"); writer.Double(snapshot.volatility_mid);
    writer.Key("ofi_rolling"); writer.Double(snapshot.ofi_rolling);
    writer.Key("window_size"); writer.Int(snapshot.window_size);
    
    // Metadata
    writer.Key("schema_version"); writer.Int(1);
    
    // Preprocessing timestamp (ISO format)
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
    writer.Key("preprocessing_timestamp"); writer.String(ss.str().c_str());
    
    // Full depth (optional - include for downstream consumers)
    writer.Key("bids");
    writer.StartArray();
    for (const auto& bid : snapshot.bids) {
        if (bid.price > 0 && bid.quantity > 0) {
            writer.StartArray();
            writer.Double(bid.price);
            writer.Double(bid.quantity);
            writer.EndArray();
        }
    }
    writer.EndArray();
    
    writer.Key("asks");
    writer.StartArray();
    for (const auto& ask : snapshot.asks) {
        if (ask.price > 0 && ask.quantity > 0) {
            writer.StartArray();
            writer.Double(ask.price);
            writer.Double(ask.quantity);
            writer.EndArray();
        }
    }
    writer.EndArray();
    
    writer.EndObject();
    
    return buffer.GetString();
}

std::string MarketDataProvider::serialize_book_delta(
    const std::string& symbol,
    const std::string& exchange,
    const std::vector<int>& side,
    const std::vector<double>& px,
    const std::vector<double>& sz,
    uint64_t ts_ns,
    uint64_t seq
) {
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("symbol"); writer.String(symbol.c_str());
    writer.Key("exchange"); writer.String(exchange.c_str());
    writer.Key("receipt_timestamp_ns"); writer.Uint64(ts_ns);
    writer.Key("seq"); writer.Uint64(seq);
    writer.Key("side"); writer.StartArray(); for (auto v: side) writer.Int(v); writer.EndArray();
    writer.Key("px"); writer.StartArray(); for (auto v: px) writer.Double(v); writer.EndArray();
    writer.Key("sz"); writer.StartArray(); for (auto v: sz) writer.Double(v); writer.EndArray();
    writer.EndObject();
    return buffer.GetString();
}

std::string MarketDataProvider::serialize_book_ckpt(
    const std::string& symbol,
    const std::string& exchange,
    const std::vector<double>& bid_px,
    const std::vector<double>& bid_sz,
    const std::vector<double>& ask_px,
    const std::vector<double>& ask_sz,
    uint64_t ts_ns,
    uint64_t seq
) {
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("symbol"); writer.String(symbol.c_str());
    writer.Key("exchange"); writer.String(exchange.c_str());
    writer.Key("receipt_timestamp_ns"); writer.Uint64(ts_ns);
    writer.Key("seq"); writer.Uint64(seq);
    writer.Key("bid_px"); writer.StartArray(); for (auto v: bid_px) writer.Double(v); writer.EndArray();
    writer.Key("bid_sz"); writer.StartArray(); for (auto v: bid_sz) writer.Double(v); writer.EndArray();
    writer.Key("ask_px"); writer.StartArray(); for (auto v: ask_px) writer.Double(v); writer.EndArray();
    writer.Key("ask_sz"); writer.StartArray(); for (auto v: ask_sz) writer.Double(v); writer.EndArray();
    writer.EndObject();
    return buffer.GetString();
}

void MarketDataProvider::emit_book_outputs(const OrderBookSnapshot& snapshot) {
    try {
        std::string symbol(snapshot.symbol.c_str());
        std::string exch(snapshot.exchange.c_str());
        // Build current price->size maps up to configured depth
        std::unordered_map<double,double> cur_b;
        std::unordered_map<double,double> cur_a;
        int depth = std::min(depth_levels_cfg_, 10);
        for (int i = 0; i < depth; ++i) {
            if (snapshot.bids[i].price > 0) cur_b[snapshot.bids[i].price] = snapshot.bids[i].quantity;
            if (snapshot.asks[i].price > 0) cur_a[snapshot.asks[i].price] = snapshot.asks[i].quantity;
        }

        auto& lb = last_bids_[symbol];
        auto& la = last_asks_[symbol];

        // Compute sparse delta if enabled
        if (emit_delta_) {
            std::vector<int> side; side.reserve(cur_b.size() + cur_a.size());
            std::vector<double> px; px.reserve(cur_b.size() + cur_a.size());
            std::vector<double> sz; sz.reserve(cur_b.size() + cur_a.size());

            // Merge keys and compare; deterministic price order
            std::set<double, std::less<double>> prices_b;
            for (auto& kv : lb) prices_b.insert(kv.first);
            for (auto& kv : cur_b) prices_b.insert(kv.first);
            for (double p : prices_b) {
                auto it_prev = lb.find(p); auto it_cur = cur_b.find(p);
                double prev = (it_prev != lb.end()) ? it_prev->second : std::numeric_limits<double>::quiet_NaN();
                bool has_prev = (it_prev != lb.end());
                bool has_cur = (it_cur != cur_b.end());
                if (!has_prev && has_cur) { side.push_back(0); px.push_back(p); sz.push_back(it_cur->second); }
                else if (has_prev && !has_cur) { side.push_back(0); px.push_back(p); sz.push_back(0.0); }
                else if (has_prev && has_cur && it_cur->second != prev) { side.push_back(0); px.push_back(p); sz.push_back(it_cur->second); }
            }
            std::set<double, std::less<double>> prices_a;
            for (auto& kv : la) prices_a.insert(kv.first);
            for (auto& kv : cur_a) prices_a.insert(kv.first);
            for (double p : prices_a) {
                auto it_prev = la.find(p); auto it_cur = cur_a.find(p);
                double prev = (it_prev != la.end()) ? it_prev->second : std::numeric_limits<double>::quiet_NaN();
                bool has_prev = (it_prev != la.end());
                bool has_cur = (it_cur != cur_a.end());
                if (!has_prev && has_cur) { side.push_back(1); px.push_back(p); sz.push_back(it_cur->second); }
                else if (has_prev && !has_cur) { side.push_back(1); px.push_back(p); sz.push_back(0.0); }
                else if (has_prev && has_cur && it_cur->second != prev) { side.push_back(1); px.push_back(p); sz.push_back(it_cur->second); }
            }

            if (!side.empty()) {
                // Allocate a unified book-stream sequence per symbol for delta/ckpt
                std::string seq_key = exch + ":book_stream:" + symbol;
                uint64_t seq = get_next_seq(seq_key);
                std::string topic = exch + "-preprocessed_book_delta-" + symbol;
                std::string payload = serialize_book_delta(symbol, exch, side, px, sz, snapshot.timestamp_ns, seq);
                zmq::message_t topic_msg(topic.size()); std::memcpy(topic_msg.data(), topic.c_str(), topic.size());
                zmq::message_t data_msg(payload.size()); std::memcpy(data_msg.data(), payload.c_str(), payload.size());
                if (orderbook_publisher_->send(topic_msg, zmq::send_flags::sndmore | zmq::send_flags::dontwait) &&
                    orderbook_publisher_->send(data_msg, zmq::send_flags::dontwait)) {
                    stats_.messages_published.fetch_add(1);
                }
            }
        }

        // Emit checkpoint if cadence elapsed
        if (emit_ckpt_) {
            uint64_t last = last_ckpt_ns_[symbol];
            bool due = (last == 0) || (snapshot.timestamp_ns >= last + static_cast<uint64_t>(ckpt_every_ms_) * 1000000ULL);
            if (due) {
                last_ckpt_ns_[symbol] = snapshot.timestamp_ns;
                std::vector<double> bid_px; bid_px.reserve(depth_levels_cfg_);
                std::vector<double> bid_sz; bid_sz.reserve(depth_levels_cfg_);
                std::vector<double> ask_px; ask_px.reserve(depth_levels_cfg_);
                std::vector<double> ask_sz; ask_sz.reserve(depth_levels_cfg_);
                int depth = std::min(depth_levels_cfg_, 10);
                for (int i = 0; i < depth; ++i) {
                    if (snapshot.bids[i].price > 0 && snapshot.bids[i].quantity > 0) {
                        bid_px.push_back(snapshot.bids[i].price);
                        bid_sz.push_back(snapshot.bids[i].quantity);
                    }
                }
                for (int i = 0; i < depth; ++i) {
                    if (snapshot.asks[i].price > 0 && snapshot.asks[i].quantity > 0) {
                        ask_px.push_back(snapshot.asks[i].price);
                        ask_sz.push_back(snapshot.asks[i].quantity);
                    }
                }
                std::string seq_key = exch + ":book_stream:" + symbol;
                uint64_t seq = get_next_seq(seq_key);
                std::string topic = exch + "-preprocessed_book_ckpt-" + symbol;
                std::string payload = serialize_book_ckpt(symbol, exch, bid_px, bid_sz, ask_px, ask_sz, snapshot.timestamp_ns, seq);
                zmq::message_t topic_msg(topic.size()); std::memcpy(topic_msg.data(), topic.c_str(), topic.size());
                zmq::message_t data_msg(payload.size()); std::memcpy(data_msg.data(), payload.c_str(), payload.size());
                if (orderbook_publisher_->send(topic_msg, zmq::send_flags::sndmore | zmq::send_flags::dontwait) &&
                    orderbook_publisher_->send(data_msg, zmq::send_flags::dontwait)) {
                    stats_.messages_published.fetch_add(1);
                }
            }
        }

        // Update last state
        last_bids_[symbol] = std::move(cur_b);
        last_asks_[symbol] = std::move(cur_a);

    } catch (const std::exception& e) {
        spdlog::warn("[MarketData] emit_book_outputs error: {}", e.what());
    }
}

std::string MarketDataProvider::canonicalize_symbol(const std::string& sym) const {
    std::string up = sym;
    std::transform(up.begin(), up.end(), up.begin(), ::toupper);
    auto it = coin_to_canonical_.find(up);
    return (it != coin_to_canonical_.end()) ? it->second : sym;
}

std::string MarketDataProvider::_coin_from_canonical(const std::string& configured_symbol) {
    // Extract coin ticker from a canonical symbol like BASE-QUOTE-PERP (e.g., BTC-USDT-PERP -> BTC)
    // Fallback to the part before first '-' or the whole string uppercased if no '-'.
    if (configured_symbol.empty()) return std::string();
    // Take segment before first '-'
    auto pos = configured_symbol.find('-');
    std::string base = (pos == std::string::npos) ? configured_symbol : configured_symbol.substr(0, pos);
    std::string out = base;
    std::transform(out.begin(), out.end(), out.begin(), ::toupper);
    return out;
}

uint64_t MarketDataProvider::get_timestamp_ns() {
    // Use system_clock for epoch-aligned timestamps (ns)
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string MarketDataProvider::build_subscription_message() {
    // Use exchange interface if available
    if (exchange_interface_) {
        return exchange_interface_->generate_subscription(symbols_, true, true);
    }
    
    // Fallback to hardcoded logic
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    
    if (exchange_ == "bybit") {
        // Bybit subscription format
        writer.StartObject();
        writer.Key("op"); writer.String("subscribe");
        writer.Key("args");
        writer.StartArray();
        
        for (const auto& symbol : symbols_) {
            // Subscribe to trades
            std::string trade_topic = "publicTrade." + symbol;
            writer.String(trade_topic.c_str());
            
            // Subscribe to orderbook
            std::string orderbook_topic = "orderbook.1." + symbol;
            writer.String(orderbook_topic.c_str());
        }
        
        writer.EndArray();
        writer.EndObject();
        
    } else if (exchange_ == "binance") {
        // Binance subscription format
        writer.StartObject();
        writer.Key("method"); writer.String("SUBSCRIBE");
        writer.Key("params");
        writer.StartArray();
        
        for (const auto& symbol : symbols_) {
            // Convert to lowercase for Binance
            std::string lower_symbol = symbol;
            std::transform(lower_symbol.begin(), lower_symbol.end(), lower_symbol.begin(), ::tolower);
            
            // Subscribe to trades
            std::string trade_stream = lower_symbol + "@trade";
            writer.String(trade_stream.c_str());
            
            // Subscribe to orderbook
            std::string orderbook_stream = lower_symbol + "@depth10@100ms";
            writer.String(orderbook_stream.c_str());
        }
        
        writer.EndArray();
        writer.Key("id"); writer.Int(1);
        writer.EndObject();
    }
    
    return buffer.GetString();
}

uint64_t MarketDataProvider::get_next_seq(const std::string& stream_key) {
    std::lock_guard<std::mutex> lock(seq_mutex_);
    return ++sequence_counters_[stream_key];
}

void MarketDataProvider::compute_book_features(OrderBookSnapshot& snapshot) {
    // Get top of book
    double best_bid_price = snapshot.bids[0].price;
    double best_bid_size = snapshot.bids[0].quantity;
    double best_ask_price = snapshot.asks[0].price;
    double best_ask_size = snapshot.asks[0].quantity;
    
    // Derived L1 features
    snapshot.midpoint = (best_bid_price + best_ask_price) / 2.0;
    snapshot.relative_spread = (best_ask_price - best_bid_price) / snapshot.midpoint;
    snapshot.breadth = best_bid_price * best_bid_size + best_ask_price * best_ask_size;
    
    // L1 imbalance
    double total_vol = best_bid_size + best_ask_size;
    snapshot.imbalance_lvl1 = (total_vol > 0) ? ((best_bid_size - best_ask_size) / total_vol) : 0.0;
    
    // Compute depth N (sum price * size across top N levels)
    snapshot.bid_depth_n = 0.0;
    snapshot.ask_depth_n = 0.0;
    
    for (int i = 0; i < 10; ++i) {
        if (snapshot.bids[i].price > 0 && snapshot.bids[i].quantity > 0) {
            snapshot.bid_depth_n += snapshot.bids[i].price * snapshot.bids[i].quantity;
        }
        if (snapshot.asks[i].price > 0 && snapshot.asks[i].quantity > 0) {
            snapshot.ask_depth_n += snapshot.asks[i].price * snapshot.asks[i].quantity;
        }
    }
    
    snapshot.depth_n = snapshot.bid_depth_n + snapshot.ask_depth_n;
    
    // Update rolling statistics
    std::string symbol_key = std::string(snapshot.symbol.c_str());
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        auto& stats = mid_stats_[symbol_key];
        
        // Update with new midpoint
        stats.update_mid(snapshot.midpoint);
        
        // Update OFI
        stats.update_ofi(best_bid_size, best_ask_size);
        
        // Get computed values
        snapshot.volatility_mid = stats.volatility();
        snapshot.ofi_rolling = stats.ofi_rolling();
        snapshot.window_size = static_cast<int>(stats.window_size());
    }
}

void MarketDataProvider::compute_trade_features(MarketTick& tick) {
    // For a single fill trade, transaction_price = price
    tick.transaction_price = tick.price;
    
    // Trading volume = price * amount
    tick.trading_volume = tick.price * tick.amount;
    
    // Update rolling statistics
    std::string symbol_key = std::string(tick.symbol.c_str());
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        auto& stats = trade_stats_[symbol_key];
        
        // Update with new transaction price
        stats.update_trade(tick.transaction_price);
        
        // Get computed volatility
        tick.volatility_transaction_price = stats.volatility();
        tick.window_size = static_cast<int>(stats.window_size());
    }
}

std::string MarketDataProvider::normalize_symbol(const std::string& symbol) {
    std::string normalized = symbol;
    // Replace underscore with dash for consistency
    std::replace(normalized.begin(), normalized.end(), '_', '-');
    return normalized;
}

bool MarketDataProvider::is_heartbeat(const std::string& topic) {
    return topic.find("-heartbeat") != std::string::npos || 
           topic.find("heartbeat") != std::string::npos;
}

} // namespace latentspeed
