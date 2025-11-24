/**
 * @file hyperliquid_adapter.h
 * @brief Skeleton adapter for Hyperliquid implementing IExchangeAdapter (Phase 3 - M1 scaffold).
 */

#pragma once

#include <memory>
#include <string>
#include <optional>
#include <vector>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <functional>

#include "adapters/exchange_adapter.h"
#include "adapters/hyperliquid_config.h"
#include <rapidjson/document.h>
namespace latentspeed::netws { class HlWsPostClient; }

// Forward declare resolver to avoid coupling in header consumers
namespace latentspeed { class HyperliquidAssetResolver; }

namespace latentspeed {

class HyperliquidAdapter final : public IExchangeAdapter {
public:
    HyperliquidAdapter();
    ~HyperliquidAdapter() override;

    // Lifecycle
    bool initialize(const std::string& api_key,
                    const std::string& api_secret,
                    bool testnet) override;
    bool connect() override;
    void disconnect() override;
    bool is_connected() const override;

    // Order ops
    OrderResponse place_order(const OrderRequest& request) override;
    OrderResponse cancel_order(const std::string& client_order_id,
                               const std::optional<std::string>& symbol = std::nullopt,
                               const std::optional<std::string>& exchange_order_id = std::nullopt) override;
    OrderResponse modify_order(const std::string& client_order_id,
                               const std::optional<std::string>& new_quantity = std::nullopt,
                               const std::optional<std::string>& new_price = std::nullopt) override;
    OrderResponse query_order(const std::string& client_order_id) override;

    // Subscriptions / callbacks
    void set_order_update_callback(OrderUpdateCallback cb) override;
    void set_fill_callback(FillCallback cb) override;
    void set_error_callback(ErrorCallback cb) override;

    // Discovery
    std::string get_exchange_name() const override { return "hyperliquid"; }

    // Open-order rehydration
    std::vector<OpenOrderBrief> list_open_orders(
        const std::optional<std::string>& category = std::nullopt,
        const std::optional<std::string>& symbol = std::nullopt,
        const std::optional<std::string>& settle_coin = std::nullopt,
        const std::optional<std::string>& base_coin = std::nullopt) override;

    // Allow engine to seed parent intent for bundled exits.
    void register_parent_intent(const std::string& client_order_id, const std::string& intent_id);

private:
    void attach_ws_handler();
    void install_private_ws_handler();
    void install_ws_subscribe_handler();  // Shared handler for ws_subscribe_ (initial + reconnect)
    void recycle_ws_client(const char* reason, std::chrono::milliseconds timeout);

    std::atomic<uint64_t> recon_last_seen_fill_ms_{0};
    std::atomic<uint64_t> recon_last_seen_update_ms_{0};

    void maybe_trigger_event_driven_reconnect_(const char* from_tag);

    // M1 scaffold state only; real client wiring arrives in later milestones
    bool connected_{false};
    bool testnet_{false};
    std::string api_key_;
    std::string api_secret_;
    HyperliquidConfig cfg_ { HyperliquidConfig::for_network(false) };
    std::unique_ptr<HyperliquidAssetResolver> resolver_;
    // Nonce + Signer (to be used in later milestones)
    std::unique_ptr<class HyperliquidNonceManager> nonce_mgr_;
    std::unique_ptr<class IHyperliquidSigner> signer_;
    std::unique_ptr<latentspeed::netws::HlWsPostClient> ws_post_;        // POST actions only (order placement)
    std::unique_ptr<latentspeed::netws::HlWsPostClient> ws_subscribe_;   // Private subscriptions only (fills, updates)
    // Guard access to ws_subscribe_ during proactive close and monitor-driven recycle
    std::mutex ws_subscribe_mutex_;
    std::function<void(const std::string&, const rapidjson::Document&)> ws_message_handler_;
    // WS monitor for auto-reconnect + resubscribe
    std::unique_ptr<std::thread> ws_monitor_thread_;
    std::atomic<bool> stop_ws_monitor_{false};
    std::optional<std::string> vault_address_{}; // Optional vault/subaccount address; omit for master
    bool disable_ws_post_{false};
    bool disable_private_ws_{false};
    bool subscribe_connected_{false};  // Track subscribe connection state independently
    int ws_post_timeout_ms_{1500};
    bool ws_first_{true};  // Prefer WS post for actions when true (HTTP fallback)
    uint64_t private_ws_connected_ms_{0};

    // Batching and rate-limit controls
    bool enable_batching_{true};
    int batch_cadence_ms_{100};
    int backoff_ms_on_429_{10000};
    bool reserve_on_429_{false};
    int reserve_weight_amount_{0};
    int reserve_weight_limit_{0};
    std::atomic<bool> stop_batcher_{false};
    std::unique_ptr<std::thread> batcher_thread_;
    std::chrono::steady_clock::time_point backoff_until_{std::chrono::steady_clock::time_point{}};
    int ioc_slippage_bps_{0};

    struct PendingOrderItem {
        int asset;
        bool is_buy;
        std::string symbol; // original symbol (e.g., BNB-USDC-PERP)
        std::string px;
        std::string sz;
        bool reduce_only;
        std::string tif; // "Ioc"|"Gtc"|"Alo"
        std::string cloid; // optional hex 128-bit
        int sz_decimals{-1};
        std::string client_order_id; // original client id from request
        std::mutex m;
        std::condition_variable cv;
        bool done{false};
        OrderResponse resp{false, "pending", std::nullopt, std::nullopt, std::nullopt, {}};
    };

    // Simple queues for IOC/GTC vs ALO
    std::mutex q_mutex_;
    std::deque<std::shared_ptr<PendingOrderItem>> q_fast_; // IOC/GTC
    std::deque<std::shared_ptr<PendingOrderItem>> q_alo_;  // ALO
    std::condition_variable q_cv_;

    // Map HL cloid (0x + 32 hex) -> original client_order_id for intent mapping
    std::mutex cloid_map_mutex_;
    std::unordered_map<std::string, std::string> cloid_to_clientid_;
    // Map original client_order_id -> HL cloid, so we can cancel by client id later
    std::unordered_map<std::string, std::string> clientid_to_cloid_;
    // Map HL cloid -> role ("tp"|"sl") for bundled brackets
    std::unordered_map<std::string, std::string> cloid_to_role_;
    // Map exchange oid -> client id and -> role for fill attribution
    std::unordered_map<std::string, std::string> oid_to_clientid_;
    std::unordered_map<std::string, std::string> oid_to_role_;
    // Track derived child (TP/SL) client ids back to their parent entry id
    std::unordered_map<std::string, std::string> child_to_parent_;

    // Recent in-flight entry orders (helps attribute fills that arrive before ack)
    struct RecentEntry {
        std::string coin;      // e.g., BNB
        bool is_buy{false};
        std::string qty;       // canonical trimmed quantity string
        std::string client_id; // original client order id
        uint64_t ts_ms{0};
    };
    std::mutex recent_mutex_;
    std::deque<RecentEntry> recent_entries_;
    static constexpr size_t kRecentMax_ = 1024;

    // Fill de-duplication across multiple private streams (userEvents vs userFills)
    std::mutex fill_dedupe_mutex_;
    std::deque<std::string> fill_dedupe_q_;
    std::unordered_set<std::string> fill_dedupe_set_;
    static constexpr size_t kFillDedupMax_ = 10000;

    // Minimal symbol -> last known fill price cache to support market fallback when BBO fetch fails
    std::mutex px_cache_mutex_;
    std::unordered_map<std::string, double> last_fill_px_;

    // Private WS liveness tracking and auto-resubscribe
    std::atomic<uint64_t> last_private_event_ms_{0};
    uint64_t last_resubscribe_ms_{0};
    static constexpr uint64_t kResubscribeQuietMs_ = 15000;   // 15s w/o private events → resubscribe
    static constexpr uint64_t kReconnectQuietMs_   = 45000;   // 45s w/o private events → reconnect
    // Runtime-configurable liveness thresholds (default to constants above)
    uint64_t resubscribe_quiet_ms_{kResubscribeQuietMs_};
    uint64_t reconnect_quiet_ms_{kReconnectQuietMs_};
    // Optional safety gate: reject fast (IOC/FOK/market/trigger) placements when private WS is stale
    // 0 disables the gate. Configurable via env LATENTSPEED_HL_PRIVATE_STALE_REJECT_MS
    uint64_t private_stale_reject_ms_{0};

    // Proactive reconnect after order placement (workaround for HL server bug)
    std::atomic<uint64_t> last_order_placement_ms_{0};
    bool enable_proactive_reconnect_{true};  // Enable by default
    static constexpr uint64_t kProactiveReconnectDelayMs_ = 150;  // Wait 150ms after order for events

    // Execution fill cursor (ms). Advanced on each processed fill for diagnostics.
    std::atomic<uint64_t> last_exec_time_cursor_ms_{0};

    static std::string ensure_hl_cloid(const std::string& maybe_id);
    void remember_cloid_mapping(const std::string& hl_cloid, const std::string& original_id);
    std::string map_back_client_id(const std::string& hl_cloid);
    void remember_cloid_role(const std::string& hl_cloid, const std::string& role);
    void remember_oid_clientid(const std::string& oid, const std::string& client_id);
    void remember_oid_role(const std::string& oid, const std::string& role);
    void remember_child_parent(const std::string& child_client_id, const std::string& parent_client_id);
    std::string parent_for_client_id(const std::string& client_id);

    static uint64_t now_ms_();
    void maybe_advance_exec_cursor(uint64_t ts_ms);

    void batcher_loop();
    void flush_queue(std::deque<std::shared_ptr<PendingOrderItem>>& q);
    bool send_signed_action_json(const std::string& payload_json, std::string& out_resp_json);
    bool try_reserve_request_weight(int weight);
    std::optional<std::pair<double,double>> fetch_top_of_book(const std::string& coin_upper);
    void confirm_resting_async(const std::string& symbol,
                               const std::string& client_order_id,
                               const std::string& exchange_order_id,
                               const std::string& cloid_hex);

    // Callbacks (stored for when WS is implemented in later milestones)
    OrderUpdateCallback order_update_cb_{};
    FillCallback fill_cb_{};
    ErrorCallback error_cb_{};
};

} // namespace latentspeed
