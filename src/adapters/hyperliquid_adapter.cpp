/**
 * @file hyperliquid_adapter.cpp
 * @brief Skeleton adapter for Hyperliquid implementing IExchangeAdapter (Phase 3 - M1 scaffold).
 */

#include "adapters/hyperliquid_adapter.h"
#include "adapters/hyperliquid_asset_resolver.h"
#include "adapters/hyperliquid_nonce.h"
#include "adapters/hyperliquid_signer.h"
#include "core/net/http_client.h"
#include "core/net/hl_ws_post_client.h"
#include "core/symbol/symbol_mapper.h"
#include "core/util/num_string.h"
#include "adapters/python_hl_signer.h"
#include <spdlog/spdlog.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <cctype>
#include <optional>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <random>
#include <cstdlib>

namespace {
inline std::string to_lower_ascii(std::string_view s) {
    std::string out(s.begin(), s.end());
    for (auto& c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return out;
}

inline std::string to_upper_ascii(std::string_view s) {
    std::string out(s.begin(), s.end());
    for (auto& c : out) if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    return out;
}

inline bool starts_with(std::string_view s, std::string_view prefix) {
    return s.rfind(prefix, 0) == 0;
}

inline bool is_hex_char(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline bool is_valid_cloid(std::string_view s) {
    if (!starts_with(s, "0x")) return false;
    if (s.size() != 34) return false; // 0x + 32 hex chars
    for (size_t i = 2; i < s.size(); ++i) if (!is_hex_char(s[i])) return false;
    return true;
}

// Normalize an epoch-like timestamp to milliseconds.
// Heuristic:
//   - < 1e10  => seconds (multiply by 1000)
//   - > 1e15  => nanoseconds (divide by 1e6)
//   - > 1e13  => microseconds (divide by 1000)
//   - otherwise assume already in milliseconds
inline uint64_t normalize_epoch_ms(uint64_t t) {
    if (t == 0) return 0ULL;
    if (t < 10000000000ULL) return t * 1000ULL;            // seconds -> ms
    if (t > 1000000000000000ULL) return t / 1000000ULL;    // ns -> ms
    if (t > 10000000000000ULL) return t / 1000ULL;         // us -> ms
    return t;                                              // ms
}

inline std::string map_tif_to_hl(std::optional<std::string> tif_in) {
    if (!tif_in.has_value() || tif_in->empty()) return std::string{"Gtc"};
    std::string t = to_lower_ascii(*tif_in);
    if (t == "gtc") return std::string{"Gtc"};
    if (t == "ioc") return std::string{"Ioc"};
    if (t == "po" || t == "post_only" || t == "postonly" || t == "alo") return std::string{"Alo"};
    return std::string{"Gtc"};
}

// Normalize a hex string to 0x + 64 lowercase hex chars (32 bytes)
inline std::string normalize_hex32(std::string s) {
    std::string out;
    if (s.rfind("0x",0)==0 || s.rfind("0X",0)==0) s = s.substr(2);
    for (char c: s) {
        if ((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')) out.push_back((char)std::tolower(c));
    }
    if (out.size() < 64) out = std::string(64 - out.size(),'0') + out;
    else if (out.size() > 64) out = out.substr(out.size()-64);
    return std::string("0x") + out;
}

inline void parse_base_quote_from_hyphen(const std::string& hyphen, std::string& base, std::string& quote) {
    auto first_dash = hyphen.find('-');
    if (first_dash == std::string::npos) { base = hyphen; quote.clear(); return; }
    base = hyphen.substr(0, first_dash);
    auto second_dash = hyphen.find('-', first_dash + 1);
    if (second_dash == std::string::npos) {
        quote = hyphen.substr(first_dash + 1);
    } else {
        quote = hyphen.substr(first_dash + 1, second_dash - first_dash - 1);
    }
}

struct BaseUrlParts { std::string scheme; std::string host; std::string port; };
inline BaseUrlParts parse_base_url(const std::string& url) {
    BaseUrlParts p{"https","", "443"};
    auto pos = url.find("://");
    std::string rest = url;
    if (pos != std::string::npos) { p.scheme = url.substr(0, pos); rest = url.substr(pos + 3); }
    auto slash = rest.find('/');
    std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    auto colon = hostport.find(':');
    if (colon == std::string::npos) { p.host = hostport; p.port = (p.scheme == "http") ? "80" : "443"; }
    else { p.host = hostport.substr(0, colon); p.port = hostport.substr(colon + 1); }
    return p;
}

// Log a safe summary of the payload being sent to HL (no secrets)
inline void log_hl_payload_summary(const std::string& payload_json) {
    try {
        rapidjson::Document d; d.Parse(payload_json.c_str());
        if (d.HasParseError() || !d.IsObject()) {
            spdlog::info("[HL] payload: invalid JSON");
            return;
        }
        const rapidjson::Value* root = &d;
        if (d.HasMember("payload") && d["payload"].IsObject()) root = &d["payload"];
        bool isMainnet = (root->HasMember("isMainnet") && (*root)["isMainnet"].IsBool()) ? (*root)["isMainnet"].GetBool() : false;
        std::string vault = (root->HasMember("vaultAddress") && (*root)["vaultAddress"].IsString()) ? (*root)["vaultAddress"].GetString() : std::string();
        std::string v_type = "none"; int v_value = -1; std::string yp_type = "none"; int yp_value = -1; size_t r_len = 0, s_len = 0;
        if (root->HasMember("signature") && (*root)["signature"].IsObject()) {
            const auto& sig = (*root)["signature"];
            if (sig.HasMember("v")) {
                if (sig["v"].IsInt()) { v_type = "int"; v_value = sig["v"].GetInt(); }
                else if (sig["v"].IsString()) { v_type = "string"; }
                else { v_type = "other"; }
            }
            if (sig.HasMember("yParity")) {
                if (sig["yParity"].IsInt()) { yp_type = "int"; yp_value = sig["yParity"].GetInt(); }
                else if (sig["yParity"].IsString()) { yp_type = "string"; }
                else { yp_type = "other"; }
            }
            if (sig.HasMember("r") && sig["r"].IsString()) r_len = std::max<size_t>(0, std::strlen(sig["r"].GetString()));
            if (sig.HasMember("s") && sig["s"].IsString()) s_len = std::max<size_t>(0, std::strlen(sig["s"].GetString()));
        }
        std::string act_type; std::string grouping; int orders_n = 0;
        int asset = -1; bool buy = false; std::string sz; std::string px; std::string tif; std::string cloid;
        bool reduce_only = false;
        if (root->HasMember("action") && (*root)["action"].IsObject()) {
            const auto& a = (*root)["action"];
            if (a.HasMember("type") && a["type"].IsString()) act_type = a["type"].GetString();
            if (a.HasMember("grouping") && a["grouping"].IsString()) grouping = a["grouping"].GetString();
            if (a.HasMember("orders") && a["orders"].IsArray()) {
                orders_n = static_cast<int>(a["orders"].Size());
                if (orders_n > 0 && a["orders"][0].IsObject()) {
                    const auto& o = a["orders"][0];
                    if (o.HasMember("a") && o["a"].IsInt()) asset = o["a"].GetInt();
                    if (o.HasMember("b") && o["b"].IsBool()) buy = o["b"].GetBool();
                    if (o.HasMember("s") && o["s"].IsString()) sz = o["s"].GetString();
                    if (o.HasMember("p") && o["p"].IsString()) px = o["p"].GetString();
                    if (o.HasMember("r") && o["r"].IsBool()) reduce_only = o["r"].GetBool();
                    if (o.HasMember("c") && o["c"].IsString()) cloid = o["c"].GetString();
                    if (o.HasMember("t") && o["t"].IsObject()) {
                        const auto& to = o["t"];
                        if (to.HasMember("limit") && to["limit"].IsObject()) {
                            const auto& lim = to["limit"];
                            if (lim.HasMember("tif") && lim["tif"].IsString()) tif = lim["tif"].GetString();
                        }
                    }
                }
            }
        }
        spdlog::info(
            "[HL] payload: mainnet={} vault={} sig[v:{} {} yParity:{} {}] sig[r_len:{} s_len:{}] action={} grouping={} orders={} first[a={},b={},s={},p={},tif={},r={},c={}]",
            (isMainnet?"true":"false"), vault,
            v_type, v_value, yp_type, yp_value, r_len, s_len,
            act_type, grouping, orders_n, asset, (buy?"buy":"sell"), sz, px, tif, (reduce_only?"true":"false"), cloid
        );
    } catch (...) {
        // Swallow any logging errors; do not disrupt live flow
    }
}
}

namespace latentspeed {

namespace {
inline int count_sig_figs(const std::string& s) {
    // Count significant figures per common rules
    bool seen_nonzero = false;
    int count = 0;
    for (char c : s) {
        if (c == '-' || c == '+') continue;
        if (c == '.') continue;
        if (c >= '0' && c <= '9') {
            if (!seen_nonzero) {
                if (c == '0') {
                    // leading zeros before first non-zero are not significant
                    continue;
                } else {
                    seen_nonzero = true;
                    count++;
                }
            } else {
                count++;
            }
        }
    }
    return count;
}

inline std::string format_fixed(double v, int decimals) {
    std::ostringstream oss;
    oss.setf(std::ios::fixed);
    if (decimals < 0) decimals = 0;
    oss << std::setprecision(decimals) << v;
    return util::trim_trailing_zeros(oss.str());
}

inline std::string snap_and_format_perp_px(const std::string& px_in, bool is_buy, int sz_decimals) {
    if (sz_decimals < 0) return px_in; // unknown; do not modify
    int max_decimals = std::max(0, 6 - sz_decimals);
    double px = 0.0;
    try { px = std::stod(px_in); } catch (...) { return px_in; }
    if (px <= 0.0) return px_in;
    double tick = std::pow(10.0, -max_decimals);
    double snapped_units = px / tick;
    double snapped_units_adj = is_buy ? std::ceil(snapped_units) : std::floor(snapped_units);
    double snapped = snapped_units_adj * tick;
    // First format to max_decimals
    std::string out = format_fixed(snapped, max_decimals);
    // If integer, allowed regardless of sig figs
    if (out.find('.') == std::string::npos) return out;
    // Enforce ≤5 significant figures by reducing decimals if needed
    int sig = count_sig_figs(out);
    if (sig <= 5) return out;
    // Reduce decimals to keep digits_before + decimals <= 5
    auto dot = out.find('.');
    int digits_before = 0;
    for (size_t i = 0; i < dot; ++i) if (out[i] >= '0' && out[i] <= '9') digits_before++;
    int allowed_decimals = std::max(0, 5 - digits_before);
    allowed_decimals = std::min(allowed_decimals, max_decimals);
    // Reformat with fewer decimals
    out = format_fixed(snapped, allowed_decimals);
    return out;
}
} // anonymous namespace

HyperliquidAdapter::HyperliquidAdapter() = default;
HyperliquidAdapter::~HyperliquidAdapter() = default;

uint64_t HyperliquidAdapter::now_ms_() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

void HyperliquidAdapter::maybe_advance_exec_cursor(uint64_t ts_ms) {
    if (!ts_ms) return;
    uint64_t prev = last_exec_time_cursor_ms_.load(std::memory_order_relaxed);
    while (ts_ms > prev &&
           !last_exec_time_cursor_ms_.compare_exchange_weak(prev, ts_ms, std::memory_order_relaxed)) {
        /* CAS retry */
    }
}

bool HyperliquidAdapter::initialize(const std::string& api_key,
                                    const std::string& api_secret,
                                    bool testnet) {
    api_key_ = api_key;
    api_secret_ = api_secret;
    testnet_ = testnet;
    cfg_ = HyperliquidConfig::for_network(testnet_);
    resolver_ = std::make_unique<HyperliquidAssetResolver>(cfg_);
    nonce_mgr_ = std::make_unique<HyperliquidNonceManager>();
    // Vault/subaccount address: include ONLY if explicitly provided.
    // Strict per-doc: omit when not trading on behalf of a vault/subaccount.
    if (const char* v = std::getenv("LATENTSPEED_HYPERLIQUID_VAULT_ADDRESS"); v && *v) {
        vault_address_ = util::to_lower_hex_address(std::string(v));
    } else {
        vault_address_ = std::nullopt;
    }
    // Control WS post usage and timeout via env (default: prefer HTTP only)
    if (const char* d = std::getenv("LATENTSPEED_HL_DISABLE_WS_POST"); d && *d) {
        std::string s(d); for (auto& c: s) c = (char)std::tolower(c);
        disable_ws_post_ = (s == "1" || s == "true" || s == "yes");
    }
    // Allow disabling private WS subscriptions to avoid snapshot floods
    if (const char* d = std::getenv("LATENTSPEED_HL_DISABLE_PRIVATE_WS"); d && *d) {
        std::string s(d); for (auto& c: s) c = (char)std::tolower(c);
        disable_private_ws_ = (s == "1" || s == "true" || s == "yes");
    }
    if (const char* t = std::getenv("LATENTSPEED_HL_WS_POST_TIMEOUT_MS"); t && *t) {
        try { ws_post_timeout_ms_ = std::max(200, std::stoi(t)); } catch (...) {}
    }
    if (const char* f = std::getenv("LATENTSPEED_HL_ACTION_WS_FIRST"); f && *f) {
        std::string s(f); for (auto& c: s) c = (char)std::tolower(c);
        ws_first_ = (s == "1" || s == "true" || s == "yes");
    }
    try { spdlog::info("[HL] action transport: ws_first={} (set LATENTSPEED_HL_ACTION_WS_FIRST to override)", (ws_first_ ? "true" : "false")); } catch (...) {}
    // Private WS liveness env overrides (optional)
    if (const char* e = std::getenv("LATENTSPEED_HL_RESUBSCRIBE_QUIET_MS"); e && *e) {
        try { resubscribe_quiet_ms_ = std::max<uint64_t>(5000, static_cast<uint64_t>(std::stoll(e))); } catch (...) {}
    }
    if (const char* e = std::getenv("LATENTSPEED_HL_RECONNECT_QUIET_MS"); e && *e) {
        try { reconnect_quiet_ms_ = std::max<uint64_t>(15000, static_cast<uint64_t>(std::stoll(e))); } catch (...) {}
    }
    try { spdlog::info("[HL-WS] liveness thresholds: resubscribe={} ms, reconnect={} ms", resubscribe_quiet_ms_, reconnect_quiet_ms_); } catch (...) {}
    // Optional private-stale placement gate (disabled by default)
    if (const char* e = std::getenv("LATENTSPEED_HL_PRIVATE_STALE_REJECT_MS"); e && *e) {
        try { private_stale_reject_ms_ = static_cast<uint64_t>(std::stoll(e)); } catch (...) { private_stale_reject_ms_ = 0; }
    }
    // Prefetch meta/spotMeta to warm caches; do not fail init on network hiccups.
    if (resolver_) (void)resolver_->refresh_all();

    // Read batching/backoff env
    if (const char* e = std::getenv("LATENTSPEED_HL_ENABLE_BATCHING"); e && *e) {
        std::string s(e); for (auto& c: s) c = (char)std::tolower(c);
        enable_batching_ = (s != "0" && s != "false" && s != "no");
    }
    if (const char* e = std::getenv("LATENTSPEED_HL_BATCH_CADENCE_MS"); e && *e) {
        try { batch_cadence_ms_ = std::max(10, std::stoi(e)); } catch(...) {}
    }
    if (const char* e = std::getenv("LATENTSPEED_HL_ON_429_BACKOFF_MS"); e && *e) {
        try { backoff_ms_on_429_ = std::max(1000, std::stoi(e)); } catch(...) {}
    }
    if (const char* e = std::getenv("LATENTSPEED_HL_RESERVE_WEIGHT_ON_429"); e && *e) {
        std::string s(e); for (auto& c: s) c = (char)std::tolower(c);
        reserve_on_429_ = (s == "1" || s == "true" || s == "yes");
    }
    if (const char* e = std::getenv("LATENTSPEED_HL_RESERVE_WEIGHT_AMOUNT"); e && *e) {
        try { reserve_weight_amount_ = std::max(1, std::stoi(e)); } catch(...) {}
    }
    if (const char* e = std::getenv("LATENTSPEED_HL_RESERVE_WEIGHT_LIMIT"); e && *e) {
        try { reserve_weight_limit_ = std::max(0, std::stoi(e)); } catch(...) {}
    }
    if (const char* e = std::getenv("LATENTSPEED_HL_IOC_MARKET_SLIPPAGE_BPS"); e && *e) {
        try { ioc_slippage_bps_ = std::max(0, std::stoi(e)); } catch(...) {}
    }

    // (no HTTP fill poller)

    // Start batcher if enabled
    if (enable_batching_) {
        stop_batcher_.store(false, std::memory_order_release);
        batcher_thread_ = std::make_unique<std::thread>(&HyperliquidAdapter::batcher_loop, this);
    }
    // Prefer Python-backed signer bridge for correctness parity with SDK.
    const char* env_py = std::getenv("LATENTSPEED_HL_SIGNER_PYTHON");
    const char* env_script = std::getenv("LATENTSPEED_HL_SIGNER_SCRIPT");
    std::string py = env_py && *env_py ? std::string(env_py) : std::string("python3");
    std::string script = env_script && *env_script ? std::string(env_script) : std::string("latentspeed/tools/hl_signer_bridge.py");
    signer_ = std::make_unique<PythonHyperliquidSigner>(py, script);
    spdlog::info("[HL] init: network={}, user={}, vault={}",
                 (testnet_ ? "testnet" : "mainnet"),
                 util::to_lower_hex_address(api_key_),
                 (vault_address_.has_value() ? *vault_address_ : std::string("<none>")));
    // M1 scaffold: do not attempt network/auth yet. Consider keys present as initialized.
    return true;
}

void HyperliquidAdapter::install_ws_subscribe_handler() {
    if (!ws_subscribe_) {
        try { spdlog::warn("[HL-WS] install_ws_subscribe_handler called but ws_subscribe_ is null"); } catch (...) {}
        return;
    }
    try { spdlog::info("[HL-WS] install_ws_subscribe_handler: installing handler on ws_subscribe_"); } catch (...) {}
    // Create handler lambda and store in member variable for reuse in reconnection path
    ws_message_handler_ = [this](const std::string& channel, const rapidjson::Document& doc) {
        spdlog::warn("[HL-WS] DEBUG: ws_message_handler_ lambda invoked for channel={}", channel);
        try {
            bool is_snapshot = (doc.HasMember("isSnapshot") && doc["isSnapshot"].IsBool() && doc["isSnapshot"].GetBool());
            try {
                if (channel == "orderUpdates" || channel == "userEvents" || channel == "userFills" || channel == "user") {
                    size_t cnt = 0;
                    if (doc.HasMember("data")) {
                        const auto& d = doc["data"];
                        if (d.IsArray()) cnt = d.Size();
                        else if (d.IsObject()) {
                            if (d.HasMember("fills") && d["fills"].IsArray()) cnt = d["fills"].Size();
                        }
                    }
                    spdlog::info("[HL-WS] rx channel={} snapshot={} items={}", channel, (is_snapshot ? "yes" : "no"), cnt);
                }
            } catch (...) {}

            // Handle legacy "user" channel: use it to seed oid->client_id via cloid mapping, then return (no emission)
            if (channel == "user") {
                try { spdlog::info("[HL-WS] handling legacy 'user' channel for mapping only"); } catch (...) {}
                try {
                    const rapidjson::Value* payload = &doc;
                    if (doc.HasMember("data") && doc["data"].IsObject()) payload = &doc["data"];
                    if (payload->IsObject() && payload->HasMember("fills") && (*payload)["fills"].IsArray()) {
                        for (auto& f : (*payload)["fills"].GetArray()) {
                            if (!f.IsObject()) continue;
                            std::string cloid;
                            std::string oid;
                            if (f.HasMember("cloid") && f["cloid"].IsString()) cloid = f["cloid"].GetString();
                            if (f.HasMember("oid") && (f["oid"].IsUint64() || f["oid"].IsInt64())) oid = std::to_string(f["oid"].GetUint64());
                            if (!cloid.empty() && !oid.empty()) {
                                std::string client_id;
                                {
                                    std::lock_guard<std::mutex> lk(cloid_map_mutex_);
                                    auto it = cloid_to_clientid_.find(to_lower_ascii(cloid));
                                    if (it != cloid_to_clientid_.end()) client_id = it->second;
                                }
                                if (!client_id.empty()) {
                                    try { remember_oid_clientid(oid, client_id); } catch (...) {}
                                }
                            }
                        }
                    }
                } catch (...) {}
                return;
            }

            // Only treat data-bearing private channels as liveness events
            if (channel == "orderUpdates" || channel == "userEvents" || channel == "userFills") {
                uint64_t now_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
                uint64_t prev = last_private_event_ms_.exchange(now_ms, std::memory_order_relaxed);
                try {
                    spdlog::info("[HL-WS] private event heartbeat channel={} ms_since_last={}",
                                 channel, (prev == 0 || now_ms < prev) ? -1 : static_cast<long long>(now_ms - prev));
                } catch (...) {}
            }
            // (no additional user branch here; handled above and returned)

            // Ignore snapshots for orderUpdates/userEvents; allow userFills snapshot to dedupe through stream
            if (is_snapshot && channel != "userFills") {
                return;
            }
            if (!doc.HasMember("data")) return;
            const auto& data = doc["data"];

            // ================================
            // orderUpdates
            // ================================
            if (channel == "orderUpdates" && data.IsArray()) {
                int item_idx = 0;
                for (auto& item : data.GetArray()) {
                    item_idx++;
                    try {
                        rapidjson::StringBuffer sb;
                        rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
                        item.Accept(writer);
                        spdlog::warn("[HL-WS] DEBUG orderUpdates item#{}: {}", item_idx, sb.GetString());
                    } catch (...) {}

                    if (!item.IsObject()) {
                        spdlog::warn("[HL-WS] DEBUG: item#{} not an object, skipping", item_idx);
                        continue;
                    }
                    spdlog::warn("[HL-WS] DEBUG: item#{} starting processing", item_idx);
                    OrderUpdate upd{};
                    std::string hlc_for_log;
                    std::string coin_symbol;
                    if (item.HasMember("order") && item["order"].IsObject()) {
                        const auto& o = item["order"];
                        if (o.HasMember("oid") && o["oid"].IsUint64()) {
                            upd.exchange_order_id = std::to_string(o["oid"].GetUint64());
                            spdlog::warn("[HL-WS] DEBUG: item#{} oid={}", item_idx, upd.exchange_order_id);
                        }
                        if (o.HasMember("cloid") && o["cloid"].IsString()) {
                            std::string hlc = o["cloid"].GetString();
                            hlc_for_log = hlc;
                            upd.client_order_id = map_back_client_id(hlc);
                        }
                        // Extract symbol (coin field) for lazy rehydration
                        if (o.HasMember("coin") && o["coin"].IsString()) {
                            coin_symbol = o["coin"].GetString();
                        }
                        // Role lookup - separate from cloid mapping to avoid lock conflicts
                        if (!hlc_for_log.empty() && !upd.exchange_order_id.empty()) {
                            std::string role;
                            {
                                std::lock_guard<std::mutex> lk(cloid_map_mutex_);
                                auto it_r = cloid_to_role_.find(to_lower_ascii(hlc_for_log));
                                if (it_r != cloid_to_role_.end()) {
                                    role = it_r->second;
                                }
                            }
                            // Call remember_oid_role OUTSIDE the lock since it acquires the same mutex
                            if (!role.empty()) {
                                remember_oid_role(upd.exchange_order_id, role);
                            }
                        }
                        if (!upd.exchange_order_id.empty() && !upd.client_order_id.empty()) {
                            remember_oid_clientid(upd.exchange_order_id, upd.client_order_id);
                        }
                    }
                    if (item.HasMember("status") && item["status"].IsString()) {
                        std::string st = item["status"].GetString();
                        if (st == "open") upd.status = "new";
                        else if (st == "filled") upd.status = "filled";
                        else if (st == "partially_filled") upd.status = "partially_filled";
                        else if (st == "canceled" || st == "cancelled" || st == "marginCanceled" || st == "scheduledCancel") upd.status = "canceled";
                        else if (st == "triggered") upd.status = "accepted";
                        else if (st == "rejected") upd.status = "rejected";
                        else if (st.size() >= 8 && st.rfind("Rejected") == st.size() - 8) { upd.status = "rejected"; upd.reason = st; }
                        else { upd.status = st; }
                    }
                    if (item.HasMember("statusTimestamp") && item["statusTimestamp"].IsUint64()) {
                        uint64_t raw_ts = item["statusTimestamp"].GetUint64();
                        upd.timestamp_ms = normalize_epoch_ms(raw_ts);
                        if (private_ws_connected_ms_ && upd.timestamp_ms + 1000 < private_ws_connected_ms_) {
                            spdlog::warn("[HL-WS] DEBUG: anti-replay filter #1 triggered for item#{} oid={}", item_idx, upd.exchange_order_id);
                            continue;
                        }
                    }
                    if (private_ws_connected_ms_ && upd.timestamp_ms && (upd.timestamp_ms + 5000 < private_ws_connected_ms_)) {
                        try {
                            spdlog::info("[HL-WS] drop orderUpdate(anti-replay) oid={} status={} ts_ms={} connect_ms={} delta_ms={}",
                                         upd.exchange_order_id, upd.status, upd.timestamp_ms,
                                         private_ws_connected_ms_, (long long)(upd.timestamp_ms - private_ws_connected_ms_));
                        } catch (...) {}
                        spdlog::warn("[HL-WS] DEBUG: anti-replay filter #2 triggered for item#{} oid={}", item_idx, upd.exchange_order_id);
                        continue;
                    }
                    spdlog::warn("[HL-WS] DEBUG: item#{} passed anti-replay filters, oid={}", item_idx, upd.exchange_order_id);

                    // Add symbol to extra_data for lazy rehydration in execution engine
                    if (!coin_symbol.empty()) {
                        std::string normalized_symbol = to_upper_ascii(coin_symbol) + "-USDC-PERP";
                        upd.extra_data["symbol"] = normalized_symbol;
                        upd.extra_data["category"] = "linear";
                        upd.extra_data["exchange"] = "hyperliquid";
                    }

                    try {
                        std::string role_m;
                        if (!upd.exchange_order_id.empty()) {
                            std::lock_guard<std::mutex> lk(cloid_map_mutex_);
                            auto itr = oid_to_role_.find(upd.exchange_order_id);
                            if (itr != oid_to_role_.end()) role_m = itr->second;
                        }
                        spdlog::info(
                            "[HL-WS] orderUpdate: oid={} cloid={} client_id={} status={} reason={} role={}",
                            upd.exchange_order_id,
                            hlc_for_log,
                            upd.client_order_id,
                            upd.status,
                            upd.reason,
                            role_m
                        );
                    } catch (...) {}
                    if (order_update_cb_) order_update_cb_(upd);
                    spdlog::warn("[HL-WS] DEBUG: item#{} processing completed", item_idx);
                }
                spdlog::warn("[HL-WS] DEBUG: orderUpdates for loop completed, processed {} items", item_idx);

                // (Step 4) Stamp "update seen" latch
                {
                    const uint64_t now_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
                    recon_last_seen_update_ms_.store(now_ms, std::memory_order_release);
                    try { spdlog::info("[HL-WS] orderUpdates: update-seen latch stamped at {}", now_ms); } catch (...) {}
                }
                maybe_trigger_event_driven_reconnect_("orderUpdates");

                // Optional debug
                try {
                    const uint64_t last_order_ms_debug = last_order_placement_ms_.load(std::memory_order_acquire);
                    spdlog::warn("[HL-WS] DEBUG after orderUpdates: enable_proactive_reconnect_={} last_order_ms={}",
                                 enable_proactive_reconnect_, last_order_ms_debug);
                } catch (...) {}

            // ================================
            // userEvents (fills)
            // ================================
            } else if (channel == "userEvents" && data.IsObject()) {
                if (data.HasMember("fills") && data["fills"].IsArray()) {
                    bool emitted_any_fill = false;  // (Step 5) track if we actually emitted a fill
                    for (auto& f : data["fills"].GetArray()) {
                        if (!f.IsObject()) continue;
                        FillData fill{};
                        if (f.HasMember("oid") && f["oid"].IsUint64()) fill.exchange_order_id = std::to_string(f["oid"].GetUint64());
                        if (f.HasMember("side") && f["side"].IsString()) {
                            std::string s = f["side"].GetString();
                            fill.side = (s == "B") ? "buy" : "sell";
                        }
                        if (f.HasMember("px") && f["px"].IsString()) fill.price = f["px"].GetString();
                        if (f.HasMember("sz") && f["sz"].IsString()) fill.quantity = f["sz"].GetString();
                        if (f.HasMember("fee") && f["fee"].IsString()) fill.fee = f["fee"].GetString();
                        if (f.HasMember("feeToken") && f["feeToken"].IsString()) fill.fee_currency = f["feeToken"].GetString();
                        if (f.HasMember("time") && f["time"].IsUint64()) {
                            fill.timestamp_ms = normalize_epoch_ms(f["time"].GetUint64());
                        }
                        if (f.HasMember("tid") && (f["tid"].IsUint64() || f["tid"].IsInt64())) fill.exec_id = std::to_string(f["tid"].GetUint64());
                        if (f.HasMember("crossed") && f["crossed"].IsBool()) fill.liquidity = f["crossed"].GetBool() ? "taker" : "maker";
                        std::string coin_for_dedup;
                        if (f.HasMember("coin") && f["coin"].IsString()) {
                            std::string coin = f["coin"].GetString();
                            coin_for_dedup = coin;
                            std::string sym_hyphen = coin;
                            if (!coin.empty() && coin[0] == '@') {
                                int idx = std::atoi(coin.c_str() + 1);
                                if (auto pair = resolver_ ? resolver_->resolve_spot_pair_by_index(idx) : std::nullopt) {
                                    sym_hyphen = pair->first + std::string("-") + pair->second;
                                }
                            } else if (!coin.empty()) {
                                sym_hyphen = coin + std::string("-USDC-PERP");
                            }
                            fill.symbol = sym_hyphen;
                            try {
                                bool looks_spot = (!coin.empty() && coin[0]=='@');
                                std::string expected = looks_spot ? coin : (coin + std::string("-USDC-PERP"));
                                spdlog::info("[HL-WS] coin.map channel=userEvents coin={} mapped_symbol={} expected_guess={}", coin, fill.symbol, expected);
                            } catch (...) {}
                        }
                        if (private_ws_connected_ms_ && fill.timestamp_ms && (fill.timestamp_ms + 5000 < private_ws_connected_ms_)) {
                            try { spdlog::info("[HL-WS] drop fill(anti-replay) channel=userEvents oid={} time_ms={} connect_ms={} delta_ms={}",
                                               fill.exchange_order_id, fill.timestamp_ms, private_ws_connected_ms_, (long long)(fill.timestamp_ms - private_ws_connected_ms_)); } catch (...) {}
                            continue;
                        }
                        try {
                            if (!fill.exchange_order_id.empty()) {
                                std::lock_guard<std::mutex> lk(cloid_map_mutex_);
                                auto itc = oid_to_clientid_.find(fill.exchange_order_id);
                                if (itc != oid_to_clientid_.end()) {
                                    fill.client_order_id = itc->second;
                                }
                                auto itr = oid_to_role_.find(fill.exchange_order_id);
                                if (itr != oid_to_role_.end()) {
                                    fill.extra_data["role"] = itr->second;
                                }
                                if (itc == oid_to_clientid_.end() || itr == oid_to_role_.end()) {
                                    try { spdlog::info("[HL-WS] mapping missing channel=userEvents oid={} intent_found={} role_found={}", fill.exchange_order_id, itc!=oid_to_clientid_.end(), itr!=oid_to_role_.end()); } catch (...) {}
                                    const uint64_t now_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch()).count());
                                    std::lock_guard<std::mutex> gr(recent_mutex_);
                                    for (auto it = recent_entries_.rbegin(); it != recent_entries_.rend(); ++it) {
                                        if (now_ms > it->ts_ms && now_ms - it->ts_ms > 10000) break;
                                        bool coin_ok = (it->coin == coin_for_dedup);
                                        bool side_ok = ((it->is_buy && fill.side == "buy") || (!it->is_buy && fill.side == "sell"));
                                        bool size_ok = false;
                                        try {
                                            double q1 = std::stod(it->qty);
                                            double q2 = std::stod(fill.quantity);
                                            size_ok = std::abs(q1 - q2) <= 1e-12;
                                        } catch (...) {
                                            size_ok = (it->qty == fill.quantity);
                                        }
                                        if (coin_ok && side_ok && size_ok) {
                                            fill.client_order_id = it->client_id;
                                            try { remember_oid_clientid(fill.exchange_order_id, it->client_id); } catch (...) {}
                                            break;
                                        }
                                    }
                                }
                            }
                        } catch (...) {}
                        try {
                            const std::string child_id = fill.client_order_id;
                            if (!child_id.empty()) fill.extra_data["child_id"] = child_id;
                            std::string parent_intent = parent_for_client_id(child_id);
                            if (!parent_intent.empty()) {
                                fill.extra_data["intent"] = parent_intent;
                            }
                        } catch (...) {}
                        if (fill.extra_data.find("intent") == fill.extra_data.end()) {
                            try { spdlog::info("[HL-WS] drop fill(no_intent) channel=userEvents oid={} cl_id={}", fill.exchange_order_id, fill.client_order_id); } catch (...) {}
                            continue;
                        }
                        if (!fill.side.empty()) fill.extra_data["side"] = fill.side;
                        if (fill.liquidity.empty()) {
                            auto itRole = fill.extra_data.find("role");
                            if (itRole != fill.extra_data.end()) {
                                std::string role_l = to_lower_ascii(itRole->second);
                                if (role_l == "maker" || role_l == "taker") {
                                    fill.liquidity = role_l;
                                }
                            }
                            if (fill.liquidity.empty()) fill.liquidity = "taker";
                        }
                        try {
                            auto itRole2 = fill.extra_data.find("role");
                            const char* role_c2 = (itRole2 != fill.extra_data.end()) ? itRole2->second.c_str() : "";
                            spdlog::info(
                                "[HL-WS] fill: channel=userEvents oid={} client_id={} role={} symbol={} side={} px={} sz={} tid={}",
                                fill.exchange_order_id,
                                fill.client_order_id,
                                role_c2,
                                fill.symbol,
                                fill.side,
                                fill.price,
                                fill.quantity,
                                fill.exec_id
                            );
                        } catch (...) {}

                        // Dedup and emit
                        bool emitted = false;
                        try {
                            std::string dedup_key = fill.exec_id;
                            if (!dedup_key.empty()) {
                                dedup_key += std::string("|") + std::to_string(fill.timestamp_ms) + std::string("|") + (fill.symbol.empty() ? "" : fill.symbol);
                            }
                            if (dedup_key.empty()) dedup_key = fill.exchange_order_id + "|" + fill.price + "|" + fill.quantity + "|" + fill.side;
                            bool seen = false;
                            {
                                std::lock_guard<std::mutex> lk(fill_dedupe_mutex_);
                                if (fill_dedupe_set_.find(dedup_key) != fill_dedupe_set_.end()) {
                                    seen = true;
                                } else {
                                    fill_dedupe_q_.push_back(dedup_key);
                                    fill_dedupe_set_.insert(dedup_key);
                                    if (fill_dedupe_q_.size() > kFillDedupMax_) {
                                        auto& old = fill_dedupe_q_.front();
                                        fill_dedupe_set_.erase(old);
                                        fill_dedupe_q_.pop_front();
                                    }
                                }
                            }
                            try { spdlog::info("[HL-WS] dedup channel=userEvents seen={} key={} tid={} oid={}", seen, dedup_key, fill.exec_id, fill.exchange_order_id); } catch (...) {}
                            if (!seen) {
                                if (fill_cb_) { try { spdlog::info("[HL-WS] emit fill channel=userEvents oid={} symbol={}", fill.exchange_order_id, fill.symbol); } catch (...) {} fill_cb_(fill); }
                                if (fill.timestamp_ms) { try { maybe_advance_exec_cursor(fill.timestamp_ms); } catch (...) {} }
                                emitted = true;
                            } else {
                                spdlog::info("[HL-WS] duplicate fill(userEvents) ignored: exec_id={} oid={}", fill.exec_id, fill.exchange_order_id);
                            }
                        } catch (...) {
                            if (fill_cb_) { fill_cb_(fill); emitted = true; }
                        }
                        emitted_any_fill = emitted_any_fill || emitted;
                    } // end for fills

                    // (Step 5) Stamp "fill seen" latch if we actually emitted at least one fill
                    if (emitted_any_fill) {
                        const uint64_t now_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count());
                        recon_last_seen_fill_ms_.store(now_ms, std::memory_order_release);
                        try { spdlog::info("[HL-WS] userEvents: fill-seen latch stamped at {}", now_ms); } catch (...) {}
                        maybe_trigger_event_driven_reconnect_("fills");
                    }
                }

            // ================================
            // userFills (fills)
            // ================================
            } else if (channel == "userFills" && data.IsObject()) {
                if (data.HasMember("fills") && data["fills"].IsArray()) {
                    bool emitted_any_fill = false;  // (Step 5) track if we actually emitted a fill
                    for (auto& f : data["fills"].GetArray()) {
                        if (!f.IsObject()) continue;
                        FillData fill{};
                        if (f.HasMember("oid") && f["oid"].IsUint64()) fill.exchange_order_id = std::to_string(f["oid"].GetUint64());
                        if (f.HasMember("side") && f["side"].IsString()) fill.side = (std::string(f["side"].GetString()) == "B") ? "buy" : "sell";
                        if (f.HasMember("px") && f["px"].IsString()) fill.price = f["px"].GetString();
                        if (f.HasMember("sz") && f["sz"].IsString()) fill.quantity = f["sz"].GetString();
                        if (f.HasMember("fee") && f["fee"].IsString()) fill.fee = f["fee"].GetString();
                        if (f.HasMember("feeToken") && f["feeToken"].IsString()) fill.fee_currency = f["feeToken"].GetString();
                        if (f.HasMember("time") && f["time"].IsUint64()) {
                            fill.timestamp_ms = normalize_epoch_ms(f["time"].GetUint64());
                        }
                        if (f.HasMember("tid") && (f["tid"].IsUint64() || f["tid"].IsInt64())) fill.exec_id = std::to_string(f["tid"].GetUint64());
                        if (f.HasMember("crossed") && f["crossed"].IsBool()) fill.liquidity = f["crossed"].GetBool() ? "taker" : "maker";
                        std::string coin_for_dedup;
                        if (f.HasMember("coin") && f["coin"].IsString()) {
                            std::string coin = f["coin"].GetString();
                            coin_for_dedup = coin;
                            std::string sym_hyphen = coin;
                            if (!coin.empty() && coin[0] == '@') {
                                int idx = std::atoi(coin.c_str() + 1);
                                if (auto pair = resolver_ ? resolver_->resolve_spot_pair_by_index(idx) : std::nullopt) {
                                    sym_hyphen = pair->first + std::string("-") + pair->second;
                                }
                            } else if (!coin.empty()) {
                                sym_hyphen = coin + std::string("-USDC-PERP");
                            }
                            fill.symbol = sym_hyphen;
                            try {
                                bool looks_spot = (!coin.empty() && coin[0]=='@');
                                std::string expected = looks_spot ? coin : (coin + std::string("-USDC-PERP"));
                                spdlog::info("[HL-WS] coin.map channel=userFills coin={} mapped_symbol={} expected_guess={}", coin, fill.symbol, expected);
                            } catch (...) {}
                        }
                        if (private_ws_connected_ms_ && fill.timestamp_ms && (fill.timestamp_ms + 5000 < private_ws_connected_ms_)) {
                            try { spdlog::info("[HL-WS] drop fill(anti-replay) channel=userFills oid={} time_ms={} connect_ms={} delta_ms={}",
                                               fill.exchange_order_id, fill.timestamp_ms, private_ws_connected_ms_, (long long)(fill.timestamp_ms - private_ws_connected_ms_)); } catch (...) {}
                            continue;
                        }
                        try {
                            if (!fill.exchange_order_id.empty()) {
                                std::lock_guard<std::mutex> lk(cloid_map_mutex_);
                                auto itc = oid_to_clientid_.find(fill.exchange_order_id);
                                if (itc != oid_to_clientid_.end()) {
                                    fill.client_order_id = itc->second;
                                }
                                auto itr = oid_to_role_.find(fill.exchange_order_id);
                                if (itr != oid_to_role_.end()) {
                                    fill.extra_data["role"] = itr->second;
                                }
                                if (itc == oid_to_clientid_.end()) {
                                    const uint64_t now_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch()).count());
                                    std::lock_guard<std::mutex> gr(recent_mutex_);
                                    for (auto it = recent_entries_.rbegin(); it != recent_entries_.rend(); ++it) {
                                        if (now_ms > it->ts_ms && now_ms - it->ts_ms > 10000) break;
                                        if (it->coin == coin_for_dedup && it->qty == fill.quantity) {
                                            fill.client_order_id = it->client_id;
                                            try { remember_oid_clientid(fill.exchange_order_id, it->client_id); } catch (...) {}
                                            break;
                                        }
                                    }
                                }
                            }
                        } catch (...) {}
                        try {
                            const std::string child_id = fill.client_order_id;
                            if (!child_id.empty()) fill.extra_data["child_id"] = child_id;
                            std::string parent_intent = parent_for_client_id(child_id);
                            if (!parent_intent.empty()) {
                                fill.extra_data["intent"] = parent_intent;
                            }
                        } catch (...) {}
                        if (fill.extra_data.find("intent") == fill.extra_data.end()) {
                            try { spdlog::info("[HL-WS] drop fill(no_intent) channel=userFills oid={} cl_id={}", fill.exchange_order_id, fill.client_order_id); } catch (...) {}
                            continue;
                        }
                        if (!fill.side.empty()) fill.extra_data["side"] = fill.side;
                        if (fill.liquidity.empty()) {
                            auto itRole = fill.extra_data.find("role");
                            if (itRole != fill.extra_data.end()) { // NOTE: if you use fill.extra_data elsewhere, keep as fill.extra_data
                                std::string role_l = to_lower_ascii(itRole->second);
                                if (role_l == "maker" || role_l == "taker") {
                                    fill.liquidity = role_l;
                                }
                            }
                            if (fill.liquidity.empty()) fill.liquidity = "taker";
                        }
                        try {
                            auto itRole2 = fill.extra_data.find("role");
                            const char* role_c2 = (itRole2 != fill.extra_data.end()) ? itRole2->second.c_str() : "";
                            spdlog::info(
                                "[HL-WS] fill: channel=userFills oid={} client_id={} role={} symbol={} side={} px={} sz={} tid={}",
                                fill.exchange_order_id,
                                fill.client_order_id,
                                role_c2,
                                fill.symbol,
                                fill.side,
                                fill.price,
                                fill.quantity,
                                fill.exec_id
                            );
                        } catch (...) {}

                        // Dedup and emit
                        bool emitted = false;
                        try {
                            std::string dedup_key = fill.exec_id;
                            if (!dedup_key.empty()) {
                                dedup_key += std::string("|") + std::to_string(fill.timestamp_ms) + std::string("|") + (fill.symbol.empty() ? "" : fill.symbol);
                            }
                            if (dedup_key.empty()) dedup_key = fill.exchange_order_id + "|" + fill.price + "|" + fill.quantity + "|" + fill.side;
                            bool seen = false;
                            {
                                std::lock_guard<std::mutex> lk(fill_dedupe_mutex_);
                                if (fill_dedupe_set_.find(dedup_key) != fill_dedupe_set_.end()) {
                                    seen = true;
                                } else {
                                    fill_dedupe_q_.push_back(dedup_key);
                                    fill_dedupe_set_.insert(dedup_key);
                                    if (fill_dedupe_q_.size() > kFillDedupMax_) {
                                        auto& old = fill_dedupe_q_.front();
                                        fill_dedupe_set_.erase(old);
                                        fill_dedupe_q_.pop_front();
                                    }
                                }
                            }
                            try { spdlog::info("[HL-WS] dedup channel=userFills seen={} key={} tid={} oid={}", seen, dedup_key, fill.exec_id, fill.exchange_order_id); } catch (...) {}
                            if (!seen) {
                                if (fill_cb_) { try { spdlog::info("[HL-WS] emit fill channel=userFills oid={} symbol={}", fill.exchange_order_id, fill.symbol); } catch (...) {} fill_cb_(fill); }
                                if (fill.timestamp_ms) { try { maybe_advance_exec_cursor(fill.timestamp_ms); } catch (...) {} }
                                emitted = true;
                            } else {
                                spdlog::info("[HL-WS] duplicate fill(userFills) ignored: exec_id={} oid={}", fill.exec_id, fill.exchange_order_id);
                            }
                        } catch (...) {
                            if (fill_cb_) { fill_cb_(fill); emitted = true; }
                        }
                        emitted_any_fill = emitted_any_fill || emitted;
                    } // end for fills

                    // (Step 5) Stamp "fill seen" latch if we actually emitted at least one fill
                    if (emitted_any_fill) {
                        const uint64_t now_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count());
                        recon_last_seen_fill_ms_.store(now_ms, std::memory_order_release);
                        try { spdlog::info("[HL-WS] userFills: fill-seen latch stamped at {}", now_ms); } catch (...) {}
                        maybe_trigger_event_driven_reconnect_("fills");
                    }
                }
            }
        } catch (const std::exception& e) {
            spdlog::warn("[HL-WS] handler error: {}", e.what());
        }
    };
    // Install the handler on ws_subscribe_
    ws_subscribe_->set_message_handler(ws_message_handler_);
}



void HyperliquidAdapter::attach_ws_handler() {
    if (!ws_post_ || !cfg_.supports_private_ws || disable_private_ws_) return;
    install_private_ws_handler();
}

void HyperliquidAdapter::recycle_ws_client(const char* reason, std::chrono::milliseconds timeout) {
    auto old_client = std::move(ws_post_);
    if (old_client) {
        auto done = std::make_shared<std::atomic<bool>>(false);
        std::thread([client = std::move(old_client), done]() mutable {
            try {
                client->close();
            } catch (...) {}
            client.reset();
            done->store(true, std::memory_order_release);
        }).detach();
        auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!done->load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (!done->load(std::memory_order_acquire)) {
            try {
                spdlog::warn("[HL-WS] {}: prior client close exceeded {} ms; continuing with fresh client",
                             (reason ? reason : "recycle"), timeout.count());
            } catch (...) {}
        }
    }
    if (cfg_.supports_ws_post && !disable_ws_post_) {
        ws_post_ = std::make_unique<latentspeed::netws::HlWsPostClient>();
        attach_ws_handler();
    } else {
        ws_post_.reset();
    }
}

// Helper to recycle ws_subscribe_ connection specifically
void recycle_ws_subscribe_client(std::unique_ptr<latentspeed::netws::HlWsPostClient>& ws_client, const char* reason, std::chrono::milliseconds timeout) {
    auto old_client = std::move(ws_client);
    if (old_client) {
        auto done = std::make_shared<std::atomic<bool>>(false);
        std::thread([client = std::move(old_client), done]() mutable {
            try {
                client->close();
            } catch (...) {}
            client.reset();
            done->store(true, std::memory_order_release);
        }).detach();
        auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!done->load(std::memory_order_acquire) && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (!done->load(std::memory_order_acquire)) {
            try {
                spdlog::warn("[HL-WS] {}: prior client close exceeded {} ms; continuing with fresh client",
                             (reason ? reason : "recycle"), timeout.count());
            } catch (...) {}
        }
    }
    ws_client = std::make_unique<latentspeed::netws::HlWsPostClient>();
}

bool HyperliquidAdapter::connect() {
    try {
        spdlog::info("[HL] connect: supports_ws_post={} disable_ws_post_={} disable_private_ws_={} ws_timeout_ms={}",
                     (cfg_.supports_ws_post ? "yes" : "no"),
                     (disable_ws_post_ ? "yes" : "no"),
                     (disable_private_ws_ ? "yes" : "no"),
                     ws_post_timeout_ms_);
    } catch (...) {}
    // Connect WS post client for POST actions when enabled; keep HTTP as fallback
    if (!ws_post_ && cfg_.supports_ws_post && !disable_ws_post_) {
        ws_post_ = std::make_unique<latentspeed::netws::HlWsPostClient>();
        bool ws_ok = ws_post_->connect(cfg_.ws_url);
        try { spdlog::info("[HL] connect: ws_post (actions only) result={} url={}", (ws_ok?"success":"failure"), cfg_.ws_url); } catch (...) {}
    }
    connected_ = true;  // engine treats adapter as connected (actions via HTTP and/or WS)

    // M5b: Connect separate WS subscribe client for private subscriptions only
    if (!ws_subscribe_ && cfg_.supports_private_ws && !disable_private_ws_) {
        ws_subscribe_ = std::make_unique<latentspeed::netws::HlWsPostClient>();
        subscribe_connected_ = ws_subscribe_->connect(cfg_.ws_url);
        try {
            spdlog::info("[HL] connect: ws_subscribe (private events) result={} url={}",
                         (subscribe_connected_ ? "success" : "failure"), cfg_.ws_url);
        } catch (...) {}
        if (subscribe_connected_) {
            // Install message handler for private streams on subscribe connection only
            install_ws_subscribe_handler();
            // Subscribe to private streams on dedicated subscribe connection
            const std::string user = util::to_lower_hex_address(api_key_);
            // Record connect time to filter out historical messages without isSnapshot marker
            private_ws_connected_ms_ = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
            ws_subscribe_->subscribe("orderUpdates", {{"user", user}});
            ws_subscribe_->subscribe("userEvents", {{"user", user}});
            ws_subscribe_->subscribe_with_bool("userFills", {{"user", user}}, {{"aggregateByTime", false}});
            try { spdlog::info("[HL-WS] ws_subscribe connected and subscribed for user {}", user); } catch (...) {}
            last_private_event_ms_.store(private_ws_connected_ms_, std::memory_order_relaxed);
            last_resubscribe_ms_ = private_ws_connected_ms_;
            // Start WS monitor thread to auto-reconnect and resubscribe on drops
            stop_ws_monitor_.store(false, std::memory_order_release);
            ws_monitor_thread_ = std::make_unique<std::thread>([this]() {
                uint64_t last_quiet_log_ms = 0;
                while (!stop_ws_monitor_.load(std::memory_order_acquire)) {
                    try {
                        // Reduce monitor cadence for faster reconnects (from 2s -> 25ms)
                        std::this_thread::sleep_for(std::chrono::milliseconds(25));
                        if (!ws_subscribe_) continue;
                        const uint64_t now_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count());
                        const uint64_t last_ev = last_private_event_ms_.load(std::memory_order_relaxed);
                        uint64_t quiet = 0;
                        if (last_ev != 0 && now_ms >= last_ev) {
                            quiet = now_ms - last_ev;
                            if (quiet > resubscribe_quiet_ms_ && (now_ms - last_quiet_log_ms) > 5000) {
                                try {
                                    uint64_t ws_last_msg = 0;
                                    uint64_t ws_last_ping = 0;
                                    {
                                        std::lock_guard<std::mutex> lk(ws_subscribe_mutex_);
                                        if (ws_subscribe_) {
                                            ws_last_msg = ws_subscribe_->get_last_msg_ms();
                                            ws_last_ping = ws_subscribe_->get_last_ping_ms();
                                        }
                                    }
                                    spdlog::info("[HL-WS] liveness monitor quiet={} ms (last_event_ms={}, ws_last_msg_ms={}, ws_last_ping_ms={}, resubscribe={} ms, reconnect={} ms)",
                                                 quiet, last_ev, ws_last_msg, ws_last_ping, resubscribe_quiet_ms_, reconnect_quiet_ms_);
                                } catch (...) {}
                                last_quiet_log_ms = now_ms;
                            }
                        }

                        bool need_reconnect = false;
                        {
                            std::lock_guard<std::mutex> lk(ws_subscribe_mutex_);
                            if (ws_subscribe_ && !ws_subscribe_->is_connected()) need_reconnect = true;
                        }
                        if (need_reconnect) {
                            try {
                                uint64_t ws_last_msg = 0;
                                uint64_t ws_last_ping = 0;
                                {
                                    std::lock_guard<std::mutex> lk(ws_subscribe_mutex_);
                                    if (ws_subscribe_) {
                                        ws_last_msg = ws_subscribe_->get_last_msg_ms();
                                        ws_last_ping = ws_subscribe_->get_last_ping_ms();
                                    }
                                }
                                spdlog::warn("[HL-WS] liveness monitor initiating recycle (now_ms={}, last_event_ms={}, quiet_ms={}, ws_last_msg_ms={}, ws_last_ping_ms={})",
                                             now_ms, last_ev, quiet, ws_last_msg, ws_last_ping);
                            } catch (...) {}
                            spdlog::warn("[HL-WS-SUBSCRIBE] detected disconnect; attempting reconnect");
                            // Properly recycle ws_subscribe_ connection (shorter max wait)
                            {
                                std::lock_guard<std::mutex> lk(ws_subscribe_mutex_);
                                recycle_ws_subscribe_client(ws_subscribe_, "reconnect(disconnect)", std::chrono::milliseconds(150));
                            }
                            bool ok = false;
                            {
                                std::lock_guard<std::mutex> lk(ws_subscribe_mutex_);
                                if (ws_subscribe_) {
                                    try {
                                        spdlog::info("[HL-WS-SUBSCRIBE] reconnect(disconnect): initiating connect(ws={})", cfg_.ws_url);
                                        ok = ws_subscribe_->connect(cfg_.ws_url);
                                    } catch (const std::exception& e) {
                                        spdlog::warn("[HL-WS-SUBSCRIBE] reconnect(disconnect) error: {}", e.what());
                                        ok = false;
                                    } catch (...) {
                                        spdlog::warn("[HL-WS-SUBSCRIBE] reconnect(disconnect) error: unknown");
                                        ok = false;
                                    }
                                }
                            }
                            // Reinstall message handler on fresh client AFTER connect succeeds
                            if (ok) {
                                std::lock_guard<std::mutex> lk(ws_subscribe_mutex_);
                                if (ws_subscribe_) ws_subscribe_->set_message_handler([this](const std::string& channel, const rapidjson::Document& doc){
                                    // Same handler as initial connection - process subscribe events only
                                    try {
                                        bool is_snapshot = (doc.HasMember("isSnapshot") && doc["isSnapshot"].IsBool() && doc["isSnapshot"].GetBool());
                                        try {
                                            if (channel == "orderUpdates" || channel == "userEvents" || channel == "userFills" || channel == "user") {
                                                size_t cnt = 0;
                                                if (doc.HasMember("data")) {
                                                    const auto& d = doc["data"];
                                                    if (d.IsArray()) cnt = d.Size();
                                                    else if (d.IsObject()) {
                                                        if (d.HasMember("fills") && d["fills"].IsArray()) cnt = d["fills"].Size();
                                                    }
                                                }
                                                spdlog::info("[HL-WS] rx channel={} snapshot={} items={}", channel, (is_snapshot?"yes":"no"), cnt);
                                            }
                                        } catch (...) {}
                                        // Legacy 'user' channel: allow ws_message_handler_ to seed oid->client_id mapping (no emission)
                                        if (channel == "user") {
                                            try { spdlog::info("[HL-WS] handling legacy 'user' channel for mapping only (reconnect)"); } catch (...) {}
                                            // fall through to ws_message_handler_
                                        }
                                        // Update liveness timestamp
                                        if (channel == "orderUpdates" || channel == "userEvents" || channel == "userFills") {
                                            last_private_event_ms_.store(static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                std::chrono::system_clock::now().time_since_epoch()).count()), std::memory_order_relaxed);
                                        }
                                        // Process events using existing handler logic
                                        if (ws_message_handler_) {
                                            ws_message_handler_(channel, doc);
                                        }
                                    } catch (...) {}
                                });
                            }
                            if (ok) {
                                const std::string user = util::to_lower_hex_address(api_key_);
                                bool s1 = false, s2 = false, s3 = false;
                                {
                                    std::lock_guard<std::mutex> lk(ws_subscribe_mutex_);
                                    if (ws_subscribe_) {
                                        s1 = ws_subscribe_->subscribe("orderUpdates", {{"user", user}});
                                        s2 = ws_subscribe_->subscribe("userEvents", {{"user", user}});
                                        s3 = ws_subscribe_->subscribe_with_bool("userFills", {{"user", user}}, {{"aggregateByTime", false}});
                                    }
                                }
                                private_ws_connected_ms_ = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::system_clock::now().time_since_epoch()).count());
                                spdlog::info("[HL-WS-SUBSCRIBE] reconnected and resubscribed for user {} (subs ok: orderUpdates={} userEvents={} userFills={})",
                                             user, (s1?"yes":"no"), (s2?"yes":"no"), (s3?"yes":"no"));
                                last_private_event_ms_.store(private_ws_connected_ms_, std::memory_order_relaxed);
                                last_resubscribe_ms_ = private_ws_connected_ms_;
                                subscribe_connected_ = true;
                                if (!(s1 && s2 && s3)) {
                                    spdlog::warn("[HL-WS-SUBSCRIBE] one or more subscriptions failed after reconnect; private events may be impaired");
                                }
                            } else {
                                spdlog::warn("[HL-WS-SUBSCRIBE] reconnect attempt failed (disconnected)");
                                subscribe_connected_ = false;
                            }
                            continue;
                        }
                    } catch (...) {}
                }
            });
        }
        return connected_;
    }
    connected_ = (ws_post_ && ws_post_->is_connected());

    // Optional preflight: verify user/API wallet recognition via a lightweight /info request
    // Enable by setting LATENTSPEED_HL_PREFLIGHT=1
    try {
        if (const char* pf = std::getenv("LATENTSPEED_HL_PREFLIGHT"); pf && (*pf=='1' || *pf=='t' || *pf=='T')) {
            const std::string user = util::to_lower_hex_address(api_key_);
            auto parts = parse_base_url(cfg_.rest_base);
            latentspeed::nethttp::HttpClient httpc;
            std::vector<latentspeed::nethttp::Header> hdrs = {{"Content-Type","application/json"}};
            rapidjson::Document req(rapidjson::kObjectType);
            auto& alloc = req.GetAllocator();
            req.AddMember("type", rapidjson::Value("openOrders", alloc), alloc);
            req.AddMember("user", rapidjson::Value(user.c_str(), alloc), alloc);
            rapidjson::StringBuffer sb; { rapidjson::Writer<rapidjson::StringBuffer> wr(sb); req.Accept(wr); }
            auto resp = httpc.request("POST", parts.scheme, parts.host, parts.port, "/info", hdrs, sb.GetString());
            spdlog::info("[HL] preflight openOrders ok for user {} ({} bytes)", user, resp.size());
        }
    } catch (const std::exception& e) {
        spdlog::warn("[HL] preflight check failed: {}", e.what());
    } catch (...) {}
    return connected_;
}

void HyperliquidAdapter::disconnect() {
    connected_ = false;
    subscribe_connected_ = false;
    // Stop WS monitor
    stop_ws_monitor_.store(true, std::memory_order_release);
    if (ws_monitor_thread_ && ws_monitor_thread_->joinable()) ws_monitor_thread_->join();
    // Close both WebSocket connections
    if (ws_post_) {
        try {
            ws_post_->close();
            ws_post_.reset();
        } catch (...) {}
    }
    if (ws_subscribe_) {
        try {
            ws_subscribe_->close();
            ws_subscribe_.reset();
        } catch (...) {}
    }
    // Stop batcher
    stop_batcher_.store(true, std::memory_order_release);
    q_cv_.notify_all();
    if (batcher_thread_ && batcher_thread_->joinable()) batcher_thread_->join();
}

bool HyperliquidAdapter::is_connected() const { return connected_; }

OrderResponse HyperliquidAdapter::place_order(const OrderRequest& request) {
    // Decide if we should use batching for this order.
    // Deterministic path (no optimistic ack) for IOC/market/trigger orders: bypass batching.
    const std::string ot_lower = to_lower_ascii(request.order_type);
    const std::string tif_lower = to_lower_ascii(request.time_in_force.has_value() ? *request.time_in_force : std::string(""));
    const bool is_ioc_like = (tif_lower == "ioc" || tif_lower == "fok");
    const bool is_market = (ot_lower == "market");
    const bool is_trigger = (ot_lower == "stop" || ot_lower == "stop_limit" ||
                             (request.extra_params.find("orderFilter") != request.extra_params.end() &&
                              to_lower_ascii(request.extra_params.at("orderFilter")) == std::string{"stoporder"}));
    const bool use_batch = enable_batching_ && !is_ioc_like && !is_market && !is_trigger;

    // Safety gate: if private WS has been quiet for too long, proactively reject fast orders
    if ((is_ioc_like || is_market || is_trigger) && private_stale_reject_ms_ > 0) {
        const uint64_t last_ev = last_private_event_ms_.load(std::memory_order_relaxed);
        const uint64_t now = now_ms_();
        if (last_ev > 0 && now > last_ev && (now - last_ev) > private_stale_reject_ms_) {
            try { spdlog::warn("[HL] private_ws_stale: quiet_ms={} threshold_ms={} (rejecting fast order cl_id={})",
                               (now - last_ev), private_stale_reject_ms_, request.client_order_id); } catch (...) {}
            return {false, "private_ws_stale", std::nullopt, request.client_order_id, std::nullopt, {}};
        }
    }

    // If batching enabled and appropriate for this order, enqueue and wait for result
    if (use_batch) {
        const bool is_spot = (request.category.has_value() && to_lower_ascii(*request.category) == std::string{"spot"});
        DefaultSymbolMapper mapper;
        std::string hyphen = mapper.to_hyphen(request.symbol, !is_spot);
        std::string base, quote; parse_base_quote_from_hyphen(hyphen, base, quote);
        if (base.empty()) {
            return {false, "hyperliquid: unable to parse symbol base/quote", std::nullopt, request.client_order_id, std::nullopt, {}};
        }
        std::optional<HlResolution> res = is_spot ? (resolver_ ? resolver_->resolve_spot(base, quote) : std::nullopt)
                                                  : (resolver_ ? resolver_->resolve_perp(base) : std::nullopt);
        if (!res || res->asset < 0) {
            if (resolver_) resolver_->refresh_all();
            res = is_spot ? resolver_->resolve_spot(base, quote) : resolver_->resolve_perp(base);
            if (!res || res->asset < 0) return {false, "hyperliquid: failed to resolve asset id from meta/spotMeta", std::nullopt, request.client_order_id, std::nullopt, {}};
        }

        auto item = std::make_shared<PendingOrderItem>();
        item->asset = res->asset;
        item->is_buy = to_lower_ascii(request.side) == std::string{"buy"};
        item->symbol = request.symbol;
        item->px = request.price.has_value() ? util::trim_trailing_zeros(*request.price) : std::string();
        item->sz = util::trim_trailing_zeros(request.quantity);
        item->reduce_only = request.reduce_only;
        item->tif = map_tif_to_hl(request.time_in_force);
        item->cloid = (!request.client_order_id.empty() && is_valid_cloid(request.client_order_id)) ? request.client_order_id : std::string();
        item->sz_decimals = res->sz_decimals;
        item->client_order_id = request.client_order_id;

        // Optional market-intent slippage cap for IOC perps
        if (!is_spot && ioc_slippage_bps_ > 0 && item->tif == std::string{"Ioc"}) {
            if (auto bbo = fetch_top_of_book(to_lower_ascii(base).empty() ? base : std::string(base)); bbo.has_value()) {
                double bid = bbo->first, ask = bbo->second;
                double slip = static_cast<double>(ioc_slippage_bps_) / 10000.0;
                auto fmt_px = [&](double v){ std::ostringstream oss; oss.setf(std::ios::fixed); oss<<std::setprecision(8)<<v; return util::trim_trailing_zeros(oss.str()); };
                if (item->is_buy && ask > 0.0) {
                    std::string target = fmt_px(ask * (1.0 + slip));
                    if (item->px.empty() || std::stod(item->px) < std::stod(target)) item->px = target;
                } else if (!item->is_buy && bid > 0.0) {
                    std::string target = fmt_px(bid * (1.0 - slip));
                    if (item->px.empty() || std::stod(item->px) > std::stod(target)) item->px = target;
                }
            }
        }

        {
            std::lock_guard<std::mutex> lk(q_mutex_);
            if (item->tif == std::string{"Alo"}) q_alo_.push_back(item);
            else q_fast_.push_back(item);
        }
        q_cv_.notify_one();

        // Wait for result with a reasonable timeout (batch cadence + network)
        std::unique_lock<std::mutex> lk(item->m);
        if (!item->cv.wait_for(lk, std::chrono::milliseconds(batch_cadence_ms_ + 1500), [&]{ return item->done; })) {
            // Timeout waiting for batch send; return expired to trigger retry upstream
            return {false, "expired", std::nullopt, request.client_order_id, std::nullopt, {}};
        }
        return item->resp;
    }
    const std::string ot = ot_lower;

    const bool is_spot = (request.category.has_value() && to_lower_ascii(*request.category) == std::string{"spot"});

    DefaultSymbolMapper mapper;
    std::string hyphen = mapper.to_hyphen(request.symbol, !is_spot);
    std::string base, quote; parse_base_quote_from_hyphen(hyphen, base, quote);
    if (base.empty()) {
        return {false, "hyperliquid: unable to parse symbol base/quote", std::nullopt, request.client_order_id, std::nullopt, {}};
    }

    std::optional<HlResolution> res;
    if (is_spot) {
        if (quote.empty()) return {false, "hyperliquid: spot order requires BASE-QUOTE pair", std::nullopt, request.client_order_id, std::nullopt, {}};
        res = resolver_ ? resolver_->resolve_spot(base, quote) : std::nullopt;
    } else {
        res = resolver_ ? resolver_->resolve_perp(base) : std::nullopt;
    }
    if (!res || res->asset < 0) {
        if (resolver_) resolver_->refresh_all();
        if (is_spot) res = resolver_->resolve_spot(base, quote); else res = resolver_->resolve_perp(base);
        if (!res || res->asset < 0) return {false, "hyperliquid: failed to resolve asset id from meta/spotMeta", std::nullopt, request.client_order_id, std::nullopt, {}};
    }

    const bool is_buy = to_lower_ascii(request.side) == std::string{"buy"};
    std::string sz = util::trim_trailing_zeros(request.quantity);
    std::string tif = map_tif_to_hl(request.time_in_force);

    rapidjson::Document action(rapidjson::kObjectType);
    auto& alloc = action.GetAllocator();
    action.AddMember("type", rapidjson::Value("order", alloc), alloc);
    rapidjson::Value orders(rapidjson::kArrayType);
    rapidjson::Value ord(rapidjson::kObjectType);
    // Use HL short keys per typed schema and match SDK field order: a, b, p, s, r, t, c?
    ord.AddMember("a", res->asset, alloc);
    ord.AddMember("b", is_buy, alloc);
    bool have_px = false;
    std::string px;
    rapidjson::Value t(rapidjson::kObjectType);
    // Build order type. Triggers have priority if indicated by extra_params.
    if (is_trigger) {
        // Map stop/TP from extra params regardless of nominal order_type
        auto itTrig = request.extra_params.find("triggerPrice");
        if (itTrig == request.extra_params.end() || itTrig->second.empty()) {
            return {false, "hyperliquid: trigger requires triggerPrice", std::nullopt, request.client_order_id, std::nullopt, {}};
        }
        const std::string trigger_px = util::trim_trailing_zeros(itTrig->second);
        std::string tpsl = "sl";
        auto itFilter = request.extra_params.find("orderFilter");
        if (itFilter != request.extra_params.end()) {
            const std::string f = to_lower_ascii(itFilter->second);
            if (f.find("takeprofit") != std::string::npos || f == "tp") tpsl = "tp";
        }
        bool is_market_trig = true;
        if (request.price.has_value() && !request.price->empty()) {
            // stop-limit: include limit price
            is_market_trig = false;
            px = util::trim_trailing_zeros(*request.price);
            if (!is_spot && res->sz_decimals >= 0) px = snap_and_format_perp_px(px, is_buy, res->sz_decimals);
            ord.AddMember("p", rapidjson::Value(px.c_str(), alloc), alloc); have_px = true;
        } else {
            // stop-market per SDK still carries a "p" in wire; derive crossed px similar to market fallback
            std::string px_eff;
            if (!is_spot) {
                if (auto bbo = fetch_top_of_book(to_upper_ascii(base)); bbo.has_value()) {
                    double bid = bbo->first, ask = bbo->second;
                    double slip = static_cast<double>(ioc_slippage_bps_) / 10000.0;
                    double target = 0.0;
                    if (is_buy && ask > 0.0) target = ask * (1.0 + slip);
                    else if (!is_buy && bid > 0.0) target = bid * (1.0 - slip);
                    if (target > 0.0) { std::ostringstream oss; oss.setf(std::ios::fixed); oss<<std::setprecision(8)<<target; px_eff = util::trim_trailing_zeros(oss.str()); }
                }
                if (px_eff.empty()) {
                    try {
                        std::lock_guard<std::mutex> lk(px_cache_mutex_);
                        auto itp = last_fill_px_.find(request.symbol);
                        if (itp != last_fill_px_.end()) {
                            double last = itp->second;
                            double slip = static_cast<double>(ioc_slippage_bps_) / 10000.0;
                            double target = is_buy ? (last * (1.0 + slip)) : (last * (1.0 - slip));
                            if (target > 0.0 && std::isfinite(target)) { std::ostringstream oss; oss.setf(std::ios::fixed); oss<<std::setprecision(8)<<target; px_eff = util::trim_trailing_zeros(oss.str()); }
                        }
                    } catch (...) {}
                }
            }
            if (!px_eff.empty()) {
                px = (res->sz_decimals >= 0) ? snap_and_format_perp_px(px_eff, is_buy, res->sz_decimals) : px_eff;
                ord.AddMember("p", rapidjson::Value(px.c_str(), alloc), alloc); have_px = true;
            } else {
                // As a last resort, include trigger price as limit px to satisfy wire; HL ignores p for isMarket triggers
                px = trigger_px;
                ord.AddMember("p", rapidjson::Value(px.c_str(), alloc), alloc); have_px = true;
            }
        }
        rapidjson::Value trig(rapidjson::kObjectType);
        trig.AddMember("isMarket", is_market_trig, alloc);
        trig.AddMember("triggerPx", rapidjson::Value(trigger_px.c_str(), alloc), alloc);
        trig.AddMember("tpsl", rapidjson::Value(tpsl.c_str(), alloc), alloc);
        t.AddMember("trigger", trig, alloc);
    } else if (ot == std::string{"limit"}) {
        if (!request.price.has_value() || request.price->empty()) {
            return {false, "hyperliquid: limit order requires price", std::nullopt, request.client_order_id, std::nullopt, {}};
        }
        px = util::trim_trailing_zeros(*request.price);
        if (!is_spot && res->sz_decimals >= 0) {
            px = snap_and_format_perp_px(px, is_buy, res->sz_decimals);
        }
        ord.AddMember("p", rapidjson::Value(px.c_str(), alloc), alloc); have_px = true;
        rapidjson::Value lim(rapidjson::kObjectType);
        lim.AddMember("tif", rapidjson::Value(tif.c_str(), alloc), alloc);
        t.AddMember("limit", lim, alloc);
    } else if (ot == std::string{"market"}) {
        // Map market to limit-IOC using provided price or last-fill-derived price (slippage-controlled)
        bool used_limit_fallback = false;
        std::string px_eff;
        if (request.price.has_value() && !request.price->empty()) {
            px_eff = util::trim_trailing_zeros(*request.price);
        } else if (!is_spot) {
            // Minimal wiring: derive from last known fill ± slippage; avoid network book fetches
            try {
                std::lock_guard<std::mutex> lk(px_cache_mutex_);
                auto itp = last_fill_px_.find(request.symbol);
                if (itp != last_fill_px_.end()) {
                    double last = itp->second;
                    double slip = static_cast<double>(ioc_slippage_bps_) / 10000.0;
                    double target = is_buy ? (last * (1.0 + slip)) : (last * (1.0 - slip));
                    if (target > 0.0 && std::isfinite(target)) {
                        std::ostringstream oss; oss.setf(std::ios::fixed); oss << std::setprecision(8) << target;
                        px_eff = util::trim_trailing_zeros(oss.str());
                    }
                }
            } catch (...) {}
        }
        if (!px_eff.empty()) {
            px = (res->sz_decimals >= 0) ? snap_and_format_perp_px(px_eff, is_buy, res->sz_decimals) : px_eff;
            ord.AddMember("p", rapidjson::Value(px.c_str(), alloc), alloc); have_px = true;
            rapidjson::Value lim(rapidjson::kObjectType);
            std::string tif_eff = "Ioc";
            lim.AddMember("tif", rapidjson::Value(tif_eff.c_str(), alloc), alloc);
            t.AddMember("limit", lim, alloc);
            used_limit_fallback = true;
        }
        if (!used_limit_fallback) {
            return {false, "hyperliquid: market order requires price or BBO-derived fallback", std::nullopt, request.client_order_id, std::nullopt, {}};
        }
    } else if (ot == std::string{"stop"} || ot == std::string{"stop_limit"}) {
        // Map stop/stop-limit to HL trigger orders per reference.
        // Require triggerPrice in extra_params.
        auto itTrig = request.extra_params.find("triggerPrice");
        if (itTrig == request.extra_params.end() || itTrig->second.empty()) {
            return {false, "hyperliquid: stop/stop-limit requires triggerPrice", std::nullopt, request.client_order_id, std::nullopt, {}};
        }
        const std::string trigger_px = util::trim_trailing_zeros(itTrig->second);
        // Determine if this is stop-loss or take-profit; default to stop-loss.
        std::string tpsl = "sl";
        auto itFilter = request.extra_params.find("orderFilter");
        if (itFilter != request.extra_params.end()) {
            const std::string f = to_lower_ascii(itFilter->second);
            if (f.find("takeprofit") != std::string::npos || f == "tp") tpsl = "tp";
        }
        // Determine if this is stop-market (no limit price) or stop-limit (has price)
        bool is_market_trig = true;
        if (ot == std::string{"stop_limit"} || (request.price.has_value() && !request.price->empty())) {
            is_market_trig = false;
        }
        if (!is_market_trig) {
            px = util::trim_trailing_zeros(*request.price);
            if (!is_spot && res->sz_decimals >= 0) {
                px = snap_and_format_perp_px(px, is_buy, res->sz_decimals);
            }
            ord.AddMember("p", rapidjson::Value(px.c_str(), alloc), alloc); have_px = true;
        } else {
            // For stop-market, include a limitPx "p" per SDK wire; use last fill ± slippage, else use triggerPx as safe fallback
            std::string px_eff;
            try {
                std::lock_guard<std::mutex> lk(px_cache_mutex_);
                auto itp = last_fill_px_.find(request.symbol);
                if (itp != last_fill_px_.end()) {
                    double last = itp->second;
                    double slip = static_cast<double>(ioc_slippage_bps_) / 10000.0;
                    double target = is_buy ? (last * (1.0 + slip)) : (last * (1.0 - slip));
                    if (target > 0.0 && std::isfinite(target)) {
                        std::ostringstream oss; oss.setf(std::ios::fixed); oss << std::setprecision(8) << target;
                        px_eff = util::trim_trailing_zeros(oss.str());
                    }
                }
            } catch (...) {}
            px = px_eff.empty() ? trigger_px : ((res->sz_decimals >= 0) ? snap_and_format_perp_px(px_eff, is_buy, res->sz_decimals) : px_eff);
            ord.AddMember("p", rapidjson::Value(px.c_str(), alloc), alloc); have_px = true;
        }
        // Build trigger object
        rapidjson::Value trig(rapidjson::kObjectType);
        trig.AddMember("isMarket", is_market_trig, alloc);
        trig.AddMember("triggerPx", rapidjson::Value(trigger_px.c_str(), alloc), alloc);
        trig.AddMember("tpsl", rapidjson::Value(tpsl.c_str(), alloc), alloc);
        t.AddMember("trigger", trig, alloc);
    } else {
        return {false, "hyperliquid: unsupported order type (supported: limit, market, stop, stop_limit)", std::nullopt, request.client_order_id, std::nullopt, {}};
    }
    // Now add s, r, t to match SDK order
    ord.AddMember("s", rapidjson::Value(sz.c_str(), alloc), alloc);
    ord.AddMember("r", request.reduce_only, alloc);
    ord.AddMember("t", t, alloc);
    if (!request.client_order_id.empty()) {
        std::string hlc = is_valid_cloid(request.client_order_id) ? request.client_order_id : ensure_hl_cloid(request.client_order_id);
        remember_cloid_mapping(hlc, request.client_order_id);
        ord.AddMember("c", rapidjson::Value(hlc.c_str(), alloc), alloc);
    }
    orders.PushBack(ord, alloc);

    // Record recent entry intent for attribution if private WS fill arrives before ack
    try {
        if (!is_spot) {
            RecentEntry re;
            re.coin = base; // perp coin
            re.is_buy = is_buy;
            re.qty = sz;
            re.client_id = request.client_order_id;
            re.ts_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
            std::lock_guard<std::mutex> g(recent_mutex_);
            recent_entries_.push_back(std::move(re));
            while (recent_entries_.size() > kRecentMax_) recent_entries_.pop_front();
        }
    } catch (...) {}

    // If bracket bundling was requested (venue-agnostic params), append TP/SL as trigger orders.
    std::string grouping_val = "na";
    try {
        auto itMode = request.extra_params.find("bracket.mode");
        if (itMode != request.extra_params.end() && to_lower_ascii(itMode->second) == std::string{"bundle"}) {
            // Side for exits is opposite of entry
            bool exit_is_buy = !is_buy;
            std::string exit_sz = request.extra_params.count("bracket.size") ? util::trim_trailing_zeros(request.extra_params.at("bracket.size")) : sz;
            bool exit_ro = true;
            auto itRO = request.extra_params.find("bracket.reduce_only");
            if (itRO != request.extra_params.end()) {
                std::string v = to_lower_ascii(itRO->second);
                exit_ro = (v == "1" || v == "true" || v == "yes");
            }
            auto add_trigger = [&](const char* which){
                std::string key_prefix = std::string("bracket.") + which + std::string(".");
                auto itType = request.extra_params.find(key_prefix + "type");
                auto itPx   = request.extra_params.find(key_prefix + "px");
                if (itPx == request.extra_params.end()) return; // require px
                std::string typ = (itType != request.extra_params.end()) ? to_lower_ascii(itType->second) : std::string("stop");
                std::string px_str = util::trim_trailing_zeros(itPx->second);
                rapidjson::Value child(rapidjson::kObjectType);
                child.AddMember("a", res->asset, alloc);
                child.AddMember("b", exit_is_buy, alloc);
                // default p = px_str, adapter will snap for perps
                std::string p_eff = px_str;
                if (!is_spot && res->sz_decimals >= 0) p_eff = snap_and_format_perp_px(px_str, exit_is_buy, res->sz_decimals);
                // Required pieces
                // Prepare order type container outside branch to keep it in scope for canonical ordering below
                rapidjson::Value tchild(rapidjson::kObjectType);
                if (typ == std::string("limit")) {
                    child.AddMember("p", rapidjson::Value(p_eff.c_str(), alloc), alloc);
                    rapidjson::Value lim(rapidjson::kObjectType);
                    lim.AddMember("tif", rapidjson::Value("Gtc", alloc), alloc);
                    tchild.AddMember("limit", lim, alloc);
                } else {
                    // stop or stop_limit
                    bool is_stop_limit = (typ == std::string("stop_limit"));
                    // Limit price for stop_limit: use limit_px if provided, else px
                    std::string limit_px = px_str;
                    auto itL = request.extra_params.find(key_prefix + "limit_px");
                    if (itL != request.extra_params.end() && !itL->second.empty()) {
                        limit_px = util::trim_trailing_zeros(itL->second);
                    }
                    std::string limit_eff = (!is_spot && res->sz_decimals >= 0) ? snap_and_format_perp_px(limit_px, exit_is_buy, res->sz_decimals) : limit_px;
                    // Include "p" for both stop and stop_limit. HL typed order expects a price string even when isMarket=true.
                    child.AddMember("p", rapidjson::Value(limit_eff.c_str(), alloc), alloc);
                    // Build trigger object
                    rapidjson::Value trig(rapidjson::kObjectType);
                    trig.AddMember("isMarket", !is_stop_limit, alloc);
                    // Enforce HL perp precision on triggerPx as well.
                    std::string trig_px_eff = px_str;
                    if (!is_spot && res->sz_decimals >= 0) trig_px_eff = snap_and_format_perp_px(px_str, exit_is_buy, res->sz_decimals);
                    trig.AddMember("triggerPx", rapidjson::Value(trig_px_eff.c_str(), alloc), alloc);
                    // Indicate role for venue classification
                    std::string tpsl = (std::string(which) == std::string("tp")) ? std::string("tp") : std::string("sl");
                    trig.AddMember("tpsl", rapidjson::Value(tpsl.c_str(), alloc), alloc);
                    tchild.AddMember("trigger", trig, alloc);
                }
                // Maintain canonical key order: a,b,p,s,r,t,c
                child.AddMember("s", rapidjson::Value(exit_sz.c_str(), alloc), alloc);
                child.AddMember("r", exit_ro, alloc);
                child.AddMember("t", tchild, alloc);
                // Generate a derived client id for the child leg so fills map cleanly back to the strategy intent.
                if (!request.client_order_id.empty()) {
                    std::string child_client_id = request.client_order_id;
                    child_client_id.append("::").append(which);
                    std::string cl_child = ensure_hl_cloid(child_client_id);
                    remember_child_parent(child_client_id, request.client_order_id);
                    remember_cloid_mapping(cl_child, child_client_id);
                    remember_cloid_role(cl_child, which);
                    child.AddMember("c", rapidjson::Value(cl_child.c_str(), alloc), alloc);
                    try { confirm_resting_async(request.symbol, child_client_id, std::string(), cl_child); } catch (...) {}
                }
                orders.PushBack(child, alloc);
            };
            // Append TP then SL if present
            add_trigger("tp");
            add_trigger("sl");
            // Grouping hint (OCO-like) when requested
            auto itOco = request.extra_params.find("bracket.oco");
            if (itOco != request.extra_params.end()) {
                std::string v = to_lower_ascii(itOco->second);
                if (v == "1" || v == "true" || v == "yes") grouping_val = "normalTpsl";
            }
        }
    } catch (...) {
        // best-effort; fall back to single order
    }

    action.AddMember("orders", orders, alloc);
    action.AddMember("grouping", rapidjson::Value(grouping_val.c_str(), alloc), alloc);

    const uint64_t nonce = nonce_mgr_ ? nonce_mgr_->next() : 0;
    spdlog::info("[HL] place: asset={} side={} sz={} type={} tif={} px={} user={} nonce={}",
                 res->asset, (is_buy?"buy":"sell"), sz, ot.c_str(), tif.c_str(),
                 (ord.HasMember("p")? ord["p"].GetString():""), util::to_lower_hex_address(api_key_), nonce);

    if (!signer_) return {false, "hyperliquid: signer not configured", std::nullopt, request.client_order_id, std::nullopt, {}};
    // Serialize action to string for signing and posting without reordering keys
    rapidjson::StringBuffer sb_act; { rapidjson::Writer<rapidjson::StringBuffer> wr(sb_act); action.Accept(wr); }
    // Provide vaultAddress = target user/subaccount address (best practice for API wallet signing)
    auto sig = signer_->sign_l1_action(
        to_lower_ascii(api_secret_),
        sb_act.GetString(),
        vault_address_,
        nonce,
        std::nullopt,
        !testnet_
    );
    if (!sig) return {false, "hyperliquid: signature unavailable (signer error)", std::nullopt, request.client_order_id, std::nullopt, {}};
    try {
        spdlog::info("[HL] signer: v={} r[0:6]={} s[0:6]={}", sig->v,
                     (sig->r.size()>=8? sig->r.substr(0,8): sig->r),
                     (sig->s.size()>=8? sig->s.substr(0,8): sig->s));
    } catch (...) {}

    // Prefer signer-built payload to avoid any divergence between signing and posting
    std::string payload_json;
    if (auto packed = signer_->build_action_payload(to_lower_ascii(api_secret_), sb_act.GetString(),
                                                    vault_address_,
                                                    nonce, !testnet_)) {
        payload_json = *packed;
    } else {
        spdlog::warn("[HL] signer build_action_payload unavailable; aborting to avoid signature mismatch");
        return {false, "hyperliquid: signer build_payload unavailable", std::nullopt, request.client_order_id, std::nullopt, {}};
    }
    // Debug: log exact JSON strings that will be posted (no redaction, per request)
    try {
        spdlog::info("[HL] action JSON (pre-sign): {}", sb_act.GetString());
        spdlog::info("[HL] final JSON payload (post): {}", payload_json);
    } catch (...) {}
    // Log safe summary of payload
    log_hl_payload_summary(payload_json);
    // Sanity check: r/s lengths should be 66 (0x + 64 hex). Warn if not; this commonly indicates malformed signature payload.
    try {
        rapidjson::Document chk; chk.Parse(payload_json.c_str());
        if (!chk.HasParseError() && chk.IsObject() && chk.HasMember("signature") && chk["signature"].IsObject()) {
            const auto& sig = chk["signature"];
            if (sig.HasMember("r") && sig["r"].IsString()) {
                size_t rl = std::strlen(sig["r"].GetString());
                if (rl != 66) spdlog::warn("[HL] signature r length unusual: {} (expected 66)", rl);
            }
            if (sig.HasMember("s") && sig["s"].IsString()) {
                size_t sl = std::strlen(sig["s"].GetString());
                if (sl != 66) spdlog::warn("[HL] signature s length unusual: {} (expected 66)", sl);
            }
        }
    } catch (...) {}

    // Send action (prefer private WS).
    std::string resp_json;
    if (!send_signed_action_json(payload_json, resp_json)) {
        return {false, "hyperliquid: action send failed", std::nullopt, request.client_order_id, std::nullopt, {}};
    }

    // Record timestamp for proactive reconnect (workaround for HL server blackout bug)
    if (enable_proactive_reconnect_) {
        last_order_placement_ms_.store(now_ms_(), std::memory_order_release);
        try {
            spdlog::info("[HL] order placed, proactive reconnect scheduled in {} ms", kProactiveReconnectDelayMs_);
        } catch (...) {}
    }

    // Parse response for exchange_order_id if resting
    rapidjson::Document dr; dr.Parse(resp_json.c_str());
    if (dr.HasParseError()) return {true, "ok", std::nullopt, request.client_order_id, std::nullopt, {}}; // treat as accepted
    // WS post returns {type:"action", payload:{ status, response:{ type:"order", data:{statuses:[...]}} }}
    const rapidjson::Value* payload_root = &dr;
    if (dr.HasMember("payload") && dr["payload"].IsObject()) payload_root = &dr["payload"];
    if (payload_root->IsObject() && payload_root->HasMember("status") && (*payload_root)["status"].IsString()) {
        std::string status = (*payload_root)["status"].GetString();
        if (status != "ok") {
            // Log raw response for diagnostics (redacted payloads are not included here)
            try { spdlog::warn("[HL] action reject status={} body={}", status, resp_json.substr(0, 512)); } catch (...) {}
            // Try to extract a more specific error message from common fields
            std::string msg = status;
            auto extract_msg = [&](const rapidjson::Value& obj){
                if (obj.HasMember("reason") && obj["reason"].IsString()) return std::string(obj["reason"].GetString());
                if (obj.HasMember("message") && obj["message"].IsString()) return std::string(obj["message"].GetString());
                if (obj.HasMember("error") && obj["error"].IsString()) return std::string(obj["error"].GetString());
                return std::string();
            };
            std::string more = extract_msg(*payload_root);
            if (more.empty() && payload_root->HasMember("response") && (*payload_root)["response"].IsObject()) {
                more = extract_msg((*payload_root)["response"]);
                if (more.empty() && (*payload_root)["response"].HasMember("data") && (*payload_root)["response"]["data"].IsObject()) {
                    auto& data = (*payload_root)["response"]["data"];
                    if (data.HasMember("statuses") && data["statuses"].IsArray()) {
                        for (auto& st : data["statuses"].GetArray()) {
                            if (!st.IsObject()) continue;
                            std::string s = extract_msg(st);
                            if (s.empty() && st.HasMember("status") && st["status"].IsString()) s = st["status"].GetString();
                            if (!s.empty()) { more = s; break; }
                        }
                    }
                }
            }
            if (!more.empty()) msg = more;
            return {false, msg, std::nullopt, request.client_order_id, std::nullopt, {}};
        }
        if (payload_root->HasMember("response") && (*payload_root)["response"].IsObject()) {
            auto& r = (*payload_root)["response"];
            if (r.HasMember("data") && r["data"].IsObject() && r["data"].HasMember("statuses") && r["data"]["statuses"].IsArray()) {
                for (auto& st : r["data"]["statuses"].GetArray()) {
                    if (st.IsObject() && st.HasMember("resting") && st["resting"].IsObject()) {
                        auto& rest = st["resting"];
                        if (rest.HasMember("oid") && rest["oid"].IsUint64()) {
                            std::string oid_s = std::to_string(rest["oid"].GetUint64());
                            // Schedule an async confirm to help the engine during brief WS hiccups
                            try {
                                std::string cl = request.client_order_id;
                                confirm_resting_async(request.symbol, cl, oid_s, cl);
                            } catch (...) {}
                            // Best-effort: remember mapping (no role here; orderUpdates will fill it in)
                            remember_oid_clientid(oid_s, request.client_order_id);
                            return {true, "ok", std::optional<std::string>(oid_s), request.client_order_id, std::optional<std::string>("accepted"), {}};
                        }
                    } else if (st.IsObject() && st.HasMember("filled") && st["filled"].IsObject()) {
                        auto& fil = st["filled"];
                        std::string oid_str;
                        if (fil.HasMember("oid") && fil["oid"].IsUint64()) oid_str = std::to_string(fil["oid"].GetUint64());
                        if (!oid_str.empty()) remember_oid_clientid(oid_str, request.client_order_id);
                        // Always skip inline fills when using dedicated subscribe connection
                        // Fills will arrive via ws_subscribe_ userFills channel
                        if (fill_cb_) {
                            spdlog::info("[HL] inline fill skipped (using dedicated subscribe connection)");
                        }
                        return {true, "ok", (oid_str.empty()? std::nullopt : std::optional<std::string>(oid_str)), request.client_order_id, std::optional<std::string>("filled"), {}};
                    }
                    // If present, propagate per-order rejection reason
                    if (st.IsObject() && st.HasMember("status") && st["status"].IsString()) {
                        std::string st_status = st["status"].GetString();
                        if (st_status != "resting" && st_status != "filled" && st_status != "accepted") {
                            std::string why;
                            if (st.HasMember("reason") && st["reason"].IsString()) why = st["reason"].GetString();
                            if (why.empty() && st.HasMember("message") && st["message"].IsString()) why = st["message"].GetString();
                            if (why.empty()) why = st_status;
                            return {false, why, std::nullopt, request.client_order_id, std::nullopt, {}};
                        }
                    }
                }
            }
        }
        return {true, "ok", std::nullopt, request.client_order_id, std::optional<std::string>("accepted"), {}};
    }
    // HTTP success shape: {"status":"ok", "response":{...}}
    if (dr.HasMember("status") && dr["status"].IsString()) {
        std::string s = dr["status"].GetString();
        if (s != "ok") {
            try { spdlog::warn("[HL] action reject status={} body={} (http)", s, resp_json.substr(0, 512)); } catch (...) {}
            std::string msg = s;
            if (dr.HasMember("response") && dr["response"].IsObject()) {
                auto& r = dr["response"];
                if (r.HasMember("reason") && r["reason"].IsString()) msg = r["reason"].GetString();
                else if (r.HasMember("message") && r["message"].IsString()) msg = r["message"].GetString();
            }
            return {false, msg, std::nullopt, request.client_order_id, std::nullopt, {}};
        }
        if (dr.HasMember("response") && dr["response"].IsObject()) {
            auto& r = dr["response"];
            if (r.HasMember("data") && r["data"].IsObject() && r["data"].HasMember("statuses") && r["data"]["statuses"].IsArray()) {
                for (auto& st : r["data"]["statuses"].GetArray()) {
                    if (st.IsObject() && st.HasMember("resting") && st["resting"].IsObject()) {
                        auto& rest = st["resting"];
                        if (rest.HasMember("oid") && rest["oid"].IsUint64()) {
                            std::string oid_s = std::to_string(rest["oid"].GetUint64());
                            try { confirm_resting_async(request.symbol, request.client_order_id, oid_s, request.client_order_id); } catch (...) {}
                            return {true, "ok", std::optional<std::string>(oid_s), request.client_order_id, std::optional<std::string>("accepted"), {}};
                        }
                    } else if (st.IsObject() && st.HasMember("filled") && st["filled"].IsObject()) {
                        auto& fil = st["filled"];
                        if (fil.HasMember("oid") && fil["oid"].IsUint64()) {
                            return {true, "ok", std::optional<std::string>(std::to_string(fil["oid"].GetUint64())), request.client_order_id, std::optional<std::string>("filled"), {}};
                        }
                    }
                    if (st.IsObject() && st.HasMember("status") && st["status"].IsString()) {
                        std::string st_status = st["status"].GetString();
                        if (st_status != "resting" && st_status != "filled" && st_status != "accepted") {
                            std::string why;
                            if (st.HasMember("reason") && st["reason"].IsString()) why = st["reason"].GetString();
                            if (why.empty() && st.HasMember("message") && st["message"].IsString()) why = st["message"].GetString();
                            if (why.empty()) why = st_status;
                            return {false, why, std::nullopt, request.client_order_id, std::nullopt, {}};
                        }
                    }
                }
            }
        }
        return {true, "ok", std::nullopt, request.client_order_id, std::optional<std::string>("accepted"), {}};
    }
    return {true, "ok", std::nullopt, request.client_order_id, std::optional<std::string>("accepted"), {}};
}

OrderResponse HyperliquidAdapter::cancel_order(const std::string& client_order_id,
                                               const std::optional<std::string>& symbol,
                                               const std::optional<std::string>& exchange_order_id) {
    const bool is_spot = false; // category unknown in signature; assume perps unless explicitly wired later
    bool have_cloid = is_valid_cloid(client_order_id);
    const bool have_oid = exchange_order_id.has_value() && !exchange_order_id->empty();
    std::string cloid_eff;
    if (!have_cloid && !have_oid) {
        // Try to resolve HL cloid from original client id
        std::lock_guard<std::mutex> lk(cloid_map_mutex_);
        auto it = clientid_to_cloid_.find(to_lower_ascii(client_order_id));
        if (it != clientid_to_cloid_.end()) {
            cloid_eff = it->second;
            have_cloid = is_valid_cloid(cloid_eff);
        }
        if (!have_cloid && !have_oid) {
            return {false, "hyperliquid: cancel requires cloid (0x+32hex) or numeric oid", std::nullopt, client_order_id, std::nullopt, {}};
        }
    }

    int asset = -1;
    if (symbol && !symbol->empty()) {
        DefaultSymbolMapper mapper;
        std::string hyphen = mapper.to_hyphen(*symbol, !is_spot);
        std::string base, quote; parse_base_quote_from_hyphen(hyphen, base, quote);
        auto res = is_spot ? (resolver_ ? resolver_->resolve_spot(base, quote) : std::nullopt)
                           : (resolver_ ? resolver_->resolve_perp(base) : std::nullopt);
        if (res) asset = res->asset;
    }
    if (asset < 0 && !have_cloid) return {false, "hyperliquid: cancel by oid requires asset id (provide symbol)", std::nullopt, client_order_id, std::nullopt, {}};

    rapidjson::Document action(rapidjson::kObjectType);
    auto& alloc = action.GetAllocator();
    if (have_cloid) {
        action.AddMember("type", rapidjson::Value("cancelByCloid", alloc), alloc);
        rapidjson::Value cancels(rapidjson::kArrayType);
        rapidjson::Value cobj(rapidjson::kObjectType);
        if (asset < 0) {
        return {false, "hyperliquid: cancelByCloid requires asset id", std::nullopt, client_order_id, std::nullopt, {}};
        }
        cobj.AddMember("asset", asset, alloc);
        const std::string& clref = cloid_eff.empty() ? client_order_id : cloid_eff;
        cobj.AddMember("cloid", rapidjson::Value(clref.c_str(), alloc), alloc);
        cancels.PushBack(cobj, alloc);
        action.AddMember("cancels", cancels, alloc);
    } else {
        action.AddMember("type", rapidjson::Value("cancel", alloc), alloc);
        rapidjson::Value cancels(rapidjson::kArrayType);
        rapidjson::Value cobj(rapidjson::kObjectType);
        cobj.AddMember("a", asset, alloc);
        // oid: we pass as string to preserve full precision; HL accepts string or uint64 for some endpoints
        uint64_t oid64 = std::stoull(*exchange_order_id);
        cobj.AddMember("o", oid64, alloc);

        cancels.PushBack(cobj, alloc);
        action.AddMember("cancels", cancels, alloc);
    }

    const uint64_t nonce = nonce_mgr_ ? nonce_mgr_->next() : 0;
    spdlog::info("[HL] cancel: clid={} symbol={} oid={} user={} nonce={}",
                 client_order_id, (symbol? *symbol: std::string("")),
                 (exchange_order_id? *exchange_order_id: std::string("")), util::to_lower_hex_address(api_key_), nonce);
    if (!signer_) return {false, "hyperliquid: signer not configured", std::nullopt, client_order_id, std::nullopt, {}};
    rapidjson::StringBuffer sb_act; { rapidjson::Writer<rapidjson::StringBuffer> wr(sb_act); action.Accept(wr); }
    auto sig = signer_->sign_l1_action(
        to_lower_ascii(api_secret_),
        sb_act.GetString(),
        vault_address_,
        nonce,
        std::nullopt,
        !testnet_
    );
    if (!sig) return {false, "hyperliquid: signature unavailable (signer error)", std::nullopt, client_order_id, std::nullopt, {}};
    try {
        spdlog::info("[HL] signer(cancel): v={} r[0:6]={} s[0:6]={}", sig->v,
                     (sig->r.size()>=8? sig->r.substr(0,8): sig->r),
                     (sig->s.size()>=8? sig->s.substr(0,8): sig->s));
    } catch (...) {}

    // Build via signer if possible
    std::string payload_json2;
    if (auto packed2 = signer_->build_action_payload(to_lower_ascii(api_secret_), sb_act.GetString(),
                                                     vault_address_,
                                                     nonce, !testnet_)) {
        payload_json2 = *packed2;
    } else {
        rapidjson::Document payload(rapidjson::kObjectType);
        {
            rapidjson::Value action_copy(rapidjson::kObjectType);
            action_copy.CopyFrom(action, payload.GetAllocator());
            payload.AddMember("action", action_copy, payload.GetAllocator());
        }
        payload.AddMember("nonce", rapidjson::Value(static_cast<uint64_t>(nonce)), payload.GetAllocator());
        rapidjson::Value sigv2(rapidjson::kObjectType);
        sigv2.AddMember("r", rapidjson::Value(sig->r.c_str(), payload.GetAllocator()), payload.GetAllocator());
        sigv2.AddMember("s", rapidjson::Value(sig->s.c_str(), payload.GetAllocator()), payload.GetAllocator());
        int v_int2 = 0;
        try {
            const std::string& vs = sig->v;
            if (!vs.empty()) {
                if (vs.rfind("0x",0)==0||vs.rfind("0X",0)==0) v_int2 = static_cast<int>(std::stoul(vs,nullptr,16));
                else v_int2 = std::stoi(vs);
            }
        } catch (...) { v_int2 = 0; }
        if (v_int2 == 0) v_int2 = 27; // default to 27 if unspecified
        sigv2.AddMember("v", rapidjson::Value(v_int2), payload.GetAllocator());
        payload.AddMember("signature", sigv2, payload.GetAllocator());
        if (vault_address_.has_value()) {
            payload.AddMember("vaultAddress", rapidjson::Value(vault_address_->c_str(), payload.GetAllocator()), payload.GetAllocator());
        }
        rapidjson::StringBuffer sb2; { rapidjson::Writer<rapidjson::StringBuffer> wr(sb2); payload.Accept(wr); }
        payload_json2 = sb2.GetString();
    }
    // Debug: log exact JSON strings that will be posted (no redaction, per request)
    try {
        spdlog::info("[HL] cancel action JSON (pre-sign): {}", sb_act.GetString());
        spdlog::info("[HL] cancel final JSON payload (post): {}", payload_json2);
    } catch (...) {}
    std::string resp_json;
    bool ok_send = false;
    // Default to HTTP first
    try {
        spdlog::info("[HL] post cancel via HTTP");
        auto parts = parse_base_url(cfg_.rest_base);
        latentspeed::nethttp::HttpClient httpc;
        std::vector<latentspeed::nethttp::Header> hdrs = {{"Content-Type","application/json"}};
        resp_json = httpc.request("POST", parts.scheme, parts.host, parts.port, "/exchange", hdrs, payload_json2);
        ok_send = true;
    } catch (...) {}
    if (!ok_send && ws_post_ && ws_post_->is_connected()) {
        spdlog::info("[HL] post cancel via WS (fallback)");
        auto resp = ws_post_->post("action", payload_json2, std::chrono::milliseconds(ws_post_timeout_ms_));
        if (resp) { resp_json = *resp; ok_send = true; }
    }
    if (!ok_send) return {false, "hyperliquid: cancel send failed", std::nullopt, client_order_id, std::nullopt, {}};
    return {true, "ok", std::nullopt, client_order_id, std::optional<std::string>("canceled"), {}};
}

OrderResponse HyperliquidAdapter::modify_order(const std::string& client_order_id,
                                               const std::optional<std::string>& new_quantity,
                                               const std::optional<std::string>& new_price) {
    if (!new_quantity.has_value() && !new_price.has_value())
        return {false, "hyperliquid: modify requires new_quantity and/or new_price", std::nullopt, client_order_id, std::nullopt, {}};
    return {false, "hyperliquid: modify not yet implemented (requires original order context)", std::nullopt, client_order_id, std::nullopt, {}};
}

OrderResponse HyperliquidAdapter::query_order(const std::string& client_order_id) {
    try {
        // Determine oid/cloid to query
        std::string oid_or_cloid;
        bool use_cloid = false;
        if (is_valid_cloid(client_order_id)) {
            oid_or_cloid = client_order_id;
            use_cloid = true;
        } else {
            std::lock_guard<std::mutex> lk(cloid_map_mutex_);
            auto it = clientid_to_cloid_.find(to_lower_ascii(client_order_id));
            if (it != clientid_to_cloid_.end() && is_valid_cloid(it->second)) {
                oid_or_cloid = it->second;
                use_cloid = true;
            }
        }
        if (oid_or_cloid.empty()) {
            return {false, "not found", std::nullopt, client_order_id, std::nullopt, {}};
        }

        const std::string user = util::to_lower_hex_address(api_key_);
        auto parts = parse_base_url(cfg_.rest_base);
        latentspeed::nethttp::HttpClient httpc;
        std::vector<latentspeed::nethttp::Header> hdrs = {{"Content-Type","application/json"}};
        rapidjson::Document req(rapidjson::kObjectType);
        auto& alloc = req.GetAllocator();
        req.AddMember("type", rapidjson::Value("orderStatus", alloc), alloc);
        req.AddMember("user", rapidjson::Value(user.c_str(), alloc), alloc);
        if (use_cloid) {
            req.AddMember("oid", rapidjson::Value(oid_or_cloid.c_str(), alloc), alloc);
        } else {
            // Fall back to client_order_id numeric parse (unlikely)
            try {
                uint64_t oid = std::stoull(client_order_id);
                req.AddMember("oid", rapidjson::Value(static_cast<uint64_t>(oid)), alloc);
            } catch (...) {
                return {false, "not found", std::nullopt, client_order_id, std::nullopt, {}};
            }
        }
        rapidjson::StringBuffer sb; { rapidjson::Writer<rapidjson::StringBuffer> wr(sb); req.Accept(wr); }
        std::string resp = httpc.request("POST", parts.scheme, parts.host, parts.port, "/info", hdrs, sb.GetString());

        rapidjson::Document d; d.Parse(resp.c_str());
        if (!d.IsObject() || d.MemberCount() == 0) {
            return {false, "not found", std::nullopt, client_order_id, std::nullopt, {}};
        }

        // Extract basic fields from common shapes
        auto as_str = [](const rapidjson::Value& v, const char* key) -> std::string {
            if (v.HasMember(key)) {
                const auto& x = v[key];
                if (x.IsString()) return std::string(x.GetString());
                if (x.IsUint64()) return std::to_string(x.GetUint64());
                if (x.IsInt64()) return std::to_string(x.GetInt64());
                if (x.IsInt())    return std::to_string(x.GetInt());
            }
            return std::string();
        };
        auto as_int = [](const rapidjson::Value& v, const char* key, int defv = -1) -> int {
            if (v.HasMember(key)) {
                const auto& x = v[key];
                if (x.IsInt()) return x.GetInt();
                if (x.IsUint()) return static_cast<int>(x.GetUint());
                if (x.IsInt64()) return static_cast<int>(x.GetInt64());
                if (x.IsUint64()) return static_cast<int>(x.GetUint64());
            }
            return defv;
        };

        const rapidjson::Value* root = &d;
        if (d.HasMember("order") && d["order"].IsObject()) root = &d["order"];
        std::string oid = as_str(*root, "oid");
        if (oid.empty()) oid = as_str(d, "oid");
        int asset = as_int(*root, "asset", -1);
        if (asset < 0) asset = as_int(d, "asset", -1);

        std::string category = (asset >= 10000) ? std::string("spot") : std::string("linear");
        std::string symbol;
        if (asset >= 10000) {
            if (resolver_) {
                auto pr = resolver_->resolve_spot_pair_by_index(asset - 10000);
                if (pr) symbol = to_upper_ascii(pr->first) + to_upper_ascii(pr->second);
            }
        } else if (asset >= 0) {
            if (resolver_) {
                auto c = resolver_->resolve_perp_coin_by_index(asset);
                if (c) symbol = *c + std::string("-USDC-PERP");
            }
        }

        OrderResponse r{true, "ok", std::nullopt, client_order_id, std::nullopt, {}};
        if (!oid.empty()) r.exchange_order_id = oid;
        if (!symbol.empty()) r.extra_data["symbol"] = symbol;
        r.extra_data["category"] = category;
        r.extra_data["exchange"] = "hyperliquid";
        return r;
    } catch (...) {
        return {false, "query failed", std::nullopt, client_order_id, std::nullopt, {}};
    }
}

void HyperliquidAdapter::set_order_update_callback(OrderUpdateCallback cb) {
    order_update_cb_ = std::move(cb);
}

void HyperliquidAdapter::set_fill_callback(FillCallback cb) {
    fill_cb_ = std::move(cb);
}

void HyperliquidAdapter::set_error_callback(ErrorCallback cb) {
    error_cb_ = std::move(cb);
}

std::vector<OpenOrderBrief> HyperliquidAdapter::list_open_orders(
    const std::optional<std::string>& category,
    const std::optional<std::string>& symbol,
    const std::optional<std::string>& settle_coin,
    const std::optional<std::string>& base_coin) {
    (void)settle_coin; (void)base_coin;
    std::vector<OpenOrderBrief> out;

    try {
        // Build POST /info {"type":"openOrders","user":<address>}
        const std::string user = util::to_lower_hex_address(api_key_);
        auto parts = parse_base_url(cfg_.rest_base);
        latentspeed::nethttp::HttpClient httpc;
        std::vector<latentspeed::nethttp::Header> hdrs = {{"Content-Type","application/json"}};
        rapidjson::Document req(rapidjson::kObjectType);
        auto& alloc = req.GetAllocator();
        req.AddMember("type", rapidjson::Value("openOrders", alloc), alloc);
        req.AddMember("user", rapidjson::Value(user.c_str(), alloc), alloc);

        rapidjson::StringBuffer sb; { rapidjson::Writer<rapidjson::StringBuffer> wr(sb); req.Accept(wr); }
        std::string resp = httpc.request("POST", parts.scheme, parts.host, parts.port, "/info", hdrs, sb.GetString());

        rapidjson::Document d; d.Parse(resp.c_str());
        const rapidjson::Value* arr = nullptr;
        if (d.IsArray()) {
            arr = &d;
        } else if (d.IsObject()) {
            if (d.HasMember("data") && d["data"].IsArray()) arr = &d["data"];
            else if (d.HasMember("openOrders") && d["openOrders"].IsArray()) arr = &d["openOrders"];
            else if (d.HasMember("orders") && d["orders"].IsArray()) arr = &d["orders"];
        }
        if (!arr) {
            try { spdlog::info("[HL] list_open_orders: empty or unexpected response shape"); } catch (...) {}
            return out;
        }

        auto as_str = [](const rapidjson::Value& v, const char* key) -> std::string {
            if (v.HasMember(key)) {
                const auto& x = v[key];
                if (x.IsString()) return std::string(x.GetString());
                if (x.IsUint64()) return std::to_string(x.GetUint64());
                if (x.IsInt64()) return std::to_string(x.GetInt64());
                if (x.IsInt())    return std::to_string(x.GetInt());
                if (x.IsBool())   return x.GetBool() ? std::string("true") : std::string("false");
            }
            return std::string();
        };
        auto as_int = [](const rapidjson::Value& v, const char* key, int defv = -1) -> int {
            if (v.HasMember(key)) {
                const auto& x = v[key];
                if (x.IsInt()) return x.GetInt();
                if (x.IsUint()) return static_cast<int>(x.GetUint());
                if (x.IsInt64()) return static_cast<int>(x.GetInt64());
                if (x.IsUint64()) return static_cast<int>(x.GetUint64());
            }
            return defv;
        };
        auto as_bool = [](const rapidjson::Value& v, const char* key, bool defv=false) -> bool {
            if (v.HasMember(key) && v[key].IsBool()) return v[key].GetBool();
            return defv;
        };

        for (auto it = arr->Begin(); it != arr->End(); ++it) {
            if (!it->IsObject()) continue;
            const auto& o = *it;
            OpenOrderBrief b;

            // Try both long and short keys (Info vs Action schema)
            std::string cloid = as_str(o, "cloid");
            if (cloid.empty() && o.HasMember("order") && o["order"].IsObject()) {
                cloid = as_str(o["order"], "cloid");
            }
            if (!cloid.empty()) {
                // Map back to original client id if we know it
                b.client_order_id = map_back_client_id(cloid);
            }
            std::string oid = as_str(o, "oid");
            if (oid.empty() && o.HasMember("order") && o["order"].IsObject()) {
                oid = as_str(o["order"], "oid");
            }
            b.exchange_order_id = oid;

            // Asset and side
            int asset = as_int(o, "asset", -1);
            if (asset < 0 && o.HasMember("order") && o["order"].IsObject()) {
                asset = as_int(o["order"], "a", -1);
            }
            bool is_buy = as_bool(o, "isBuy", false);
            if (!is_buy && o.HasMember("order") && o["order"].IsObject()) {
                if (o["order"].HasMember("b") && o["order"]["b"].IsBool()) is_buy = o["order"]["b"].GetBool();
            }
            b.side = is_buy ? "buy" : "sell";

            // Order type (heuristic): trigger if trigger section present
            bool is_trigger = false;
            if (o.HasMember("t") && o["t"].IsObject() && o["t"].HasMember("trigger") && o["t"]["trigger"].IsObject()) {
                is_trigger = true;
            } else if (o.HasMember("type") && o["type"].IsString()) {
                std::string t = to_lower_ascii(o["type"].GetString());
                is_trigger = (t.find("trigger") != std::string::npos || t.find("stop") != std::string::npos);
            }
            b.order_type = is_trigger ? std::string("stop") : std::string("limit");

            // Quantity (best-effort)
            std::string qty = as_str(o, "s");
            if (qty.empty()) qty = as_str(o, "sz");
            if (qty.empty() && o.HasMember("order") && o["order"].IsObject()) qty = as_str(o["order"], "s");
            b.qty = qty;

            // Reduce-only
            bool ro = as_bool(o, "reduceOnly", false);
            if (!ro && o.HasMember("order") && o["order"].IsObject() && o["order"].HasMember("r") && o["order"]["r"].IsBool()) ro = o["order"]["r"].GetBool();
            b.reduce_only = ro;

            // Map asset to symbol and category; filter if caller requests a category/symbol
            if (asset >= 10000) {
                // Spot
                b.category = "spot";
                std::string sym_compact;
                if (resolver_) {
                    auto pr = resolver_->resolve_spot_pair_by_index(asset - 10000);
                    if (pr) {
                        sym_compact = to_upper_ascii(pr->first) + to_upper_ascii(pr->second);
                    }
                }
                b.symbol = sym_compact;
            } else if (asset >= 0) {
                // Perp
                b.category = "linear";
                std::string coin;
                if (resolver_) {
                    auto c = resolver_->resolve_perp_coin_by_index(asset);
                    if (c) coin = *c; // already uppercased by resolver
                }
                b.symbol = coin.empty() ? std::string() : (coin + std::string("USDC"));
            }

            // Apply optional filters
            if (category && !category->empty()) {
                if (to_lower_ascii(*category) != to_lower_ascii(b.category)) continue;
            }
            if (symbol && !symbol->empty()) {
                if (to_upper_ascii(*symbol) != to_upper_ascii(b.symbol)) continue;
            }

            // Keep exchange oid in extra for convenience
            if (!b.exchange_order_id.empty()) b.extra["orderId"] = b.exchange_order_id;
            out.emplace_back(std::move(b));
        }
    } catch (const std::exception& e) {
        try { spdlog::warn("[HL] list_open_orders failed: {}", e.what()); } catch (...) {}
    }
    return out;
}

void HyperliquidAdapter::batcher_loop() {
    auto next_flush = std::chrono::steady_clock::now() + std::chrono::milliseconds(batch_cadence_ms_);
    while (!stop_batcher_.load(std::memory_order_acquire)) {
        std::unique_lock<std::mutex> lk(q_mutex_);
        if (q_fast_.empty() && q_alo_.empty()) {
            q_cv_.wait_for(lk, std::chrono::milliseconds(batch_cadence_ms_));
        } else {
            q_cv_.wait_until(lk, next_flush);
        }
        if (stop_batcher_.load(std::memory_order_acquire)) break;
        auto now = std::chrono::steady_clock::now();
        if (now < next_flush) continue;
        next_flush = now + std::chrono::milliseconds(batch_cadence_ms_);

        // Apply address-based backoff
        if (backoff_until_ != std::chrono::steady_clock::time_point{} && now < backoff_until_) {
            auto reply_rate_limited = [&](std::deque<std::shared_ptr<PendingOrderItem>>& q) {
                while (!q.empty()) {
                    auto it = q.front(); q.pop_front();
                    std::lock_guard<std::mutex> g(it->m);
                    it->done = true;
                    it->resp = {false, std::string("rate_limited"), std::nullopt, std::nullopt, std::nullopt, {}};
                    it->cv.notify_all();
                }
            };
            reply_rate_limited(q_fast_);
            reply_rate_limited(q_alo_);
            continue;
        }

        if (!q_fast_.empty()) flush_queue(q_fast_);
        if (!q_alo_.empty()) flush_queue(q_alo_);
    }
}

void HyperliquidAdapter::flush_queue(std::deque<std::shared_ptr<PendingOrderItem>>& q) {
    if (q.empty()) return;
    rapidjson::Document action(rapidjson::kObjectType);
    auto& alloc = action.GetAllocator();
    action.AddMember("type", rapidjson::Value("order", alloc), alloc);
    rapidjson::Value orders(rapidjson::kArrayType);
    std::vector<std::shared_ptr<PendingOrderItem>> items;
    while (!q.empty()) { items.push_back(q.front()); q.pop_front(); }
    for (const auto& it : items) {
        rapidjson::Value ord(rapidjson::kObjectType);
        ord.AddMember("a", it->asset, alloc);
        ord.AddMember("b", it->is_buy, alloc);
        // Ensure cloid present for mapping
        if (it->cloid.empty() && !it->client_order_id.empty()) {
            it->cloid = is_valid_cloid(it->client_order_id) ? it->client_order_id : ensure_hl_cloid(it->client_order_id);
            remember_cloid_mapping(it->cloid, it->client_order_id);
        }
        if (!it->px.empty()) {
            std::string px2 = (it->sz_decimals >= 0) ? snap_and_format_perp_px(it->px, it->is_buy, it->sz_decimals) : it->px;
            ord.AddMember("p", rapidjson::Value(px2.c_str(), alloc), alloc);
        }
        ord.AddMember("s", rapidjson::Value(it->sz.c_str(), alloc), alloc);
        ord.AddMember("r", it->reduce_only, alloc);
        rapidjson::Value t(rapidjson::kObjectType);
        rapidjson::Value lim(rapidjson::kObjectType);
        lim.AddMember("tif", rapidjson::Value(it->tif.c_str(), alloc), alloc);
        t.AddMember("limit", lim, alloc);
        ord.AddMember("t", t, alloc);
        if (!it->cloid.empty()) ord.AddMember("c", rapidjson::Value(it->cloid.c_str(), alloc), alloc);
        orders.PushBack(ord, alloc);
    }
    action.AddMember("orders", orders, alloc);
    action.AddMember("grouping", rapidjson::Value("na", alloc), alloc);

    rapidjson::StringBuffer sb_act; { rapidjson::Writer<rapidjson::StringBuffer> wr(sb_act); action.Accept(wr); }
    const uint64_t nonce = nonce_mgr_ ? nonce_mgr_->next() : 0;
    if (!signer_) {
        for (auto& it : items) { std::lock_guard<std::mutex> g(it->m); it->done = true; it->resp = {false, "hyperliquid: signer not configured", std::nullopt, std::nullopt, std::nullopt, {}}; it->cv.notify_all(); }
        return;
    }
    auto packed = signer_->build_action_payload(to_lower_ascii(api_secret_), sb_act.GetString(), vault_address_, nonce, !testnet_);
    if (!packed) {
        for (auto& it : items) { std::lock_guard<std::mutex> g(it->m); it->done = true; it->resp = {false, "hyperliquid: signer build_payload unavailable", std::nullopt, std::nullopt, std::nullopt, {}}; it->cv.notify_all(); }
        return;
    }
    std::string resp_json;
    bool ok = send_signed_action_json(*packed, resp_json);
    if (ok && enable_proactive_reconnect_) {
        const uint64_t now = now_ms_();
        // Reset latches so we require both signals AFTER this placement
        recon_last_seen_fill_ms_.store(0, std::memory_order_release);
        recon_last_seen_update_ms_.store(0, std::memory_order_release);
        last_order_placement_ms_.store(now, std::memory_order_release);
        try { spdlog::info("[HL] batch placed, proactive reconnect ARMED at {}", now); } catch (...) {}
    }
    if (!ok) {
        bool rate_limited = (resp_json.find("HTTP status 429") != std::string::npos);
        if (rate_limited) {
            backoff_until_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(backoff_ms_on_429_);
            if (reserve_on_429_ && reserve_weight_amount_ > 0 && reserve_weight_limit_ > 0) {
                if (try_reserve_request_weight(std::min(reserve_weight_amount_, reserve_weight_limit_))) {
                    reserve_weight_limit_ = std::max(0, reserve_weight_limit_ - reserve_weight_amount_);
                }
            }
        }
        for (auto& it : items) {
            std::lock_guard<std::mutex> g(it->m);
            it->done = true;
            it->resp = {false, rate_limited ? std::string("rate_limited") : std::string("hyperliquid: action send failed"), std::nullopt, std::nullopt, std::nullopt, {}};
            it->cv.notify_all();
        }
        return;
    }

    rapidjson::Document dr; dr.Parse(resp_json.c_str());
    try { spdlog::info("[HL] batch response (trunc512): {}", resp_json.substr(0, 512)); } catch (...) {}
    const rapidjson::Value* payload_root = &dr;
    if (dr.HasMember("payload") && dr["payload"].IsObject()) payload_root = &dr["payload"];
    bool ok_status = (payload_root->IsObject() && payload_root->HasMember("status") && (*payload_root)["status"].IsString() && std::string((*payload_root)["status"].GetString()) == "ok");
    if (!ok_status) {
        auto extract_msg = [&](const rapidjson::Value& obj){
            if (obj.IsString()) return std::string(obj.GetString());
            if (obj.IsObject()) {
                if (obj.HasMember("reason") && obj["reason"].IsString()) return std::string(obj["reason"].GetString());
                if (obj.HasMember("message") && obj["message"].IsString()) return std::string(obj["message"].GetString());
                if (obj.HasMember("error") && obj["error"].IsString()) return std::string(obj["error"].GetString());
            }
            return std::string();
        };
        std::string msg = extract_msg(*payload_root);
        if (msg.empty() && payload_root->HasMember("response")) msg = extract_msg((*payload_root)["response"]);
        if (msg.empty() && payload_root->HasMember("response") && (*payload_root)["response"].IsObject()) {
            auto& r = (*payload_root)["response"];
            if (r.HasMember("data") && r["data"].IsObject() && r["data"].HasMember("statuses") && r["data"]["statuses"].IsArray()) {
                for (auto& st : r["data"]["statuses"].GetArray()) {
                    msg = extract_msg(st);
                    if (!msg.empty()) break;
                }
            }
        }
        for (auto& it : items) { std::lock_guard<std::mutex> g(it->m); it->done = true; it->resp = {false, msg.empty()? std::string("rejected"): msg, std::nullopt, std::nullopt, std::nullopt, {}}; it->cv.notify_all(); }
        return;
    }
    if (payload_root->HasMember("response") && (*payload_root)["response"].IsObject()) {
        auto& r = (*payload_root)["response"];
        if (r.HasMember("data") && r["data"].IsObject() && r["data"].HasMember("statuses") && r["data"]["statuses"].IsArray()) {
            size_t idx = 0;
            for (auto& st : r["data"]["statuses"].GetArray()) {
                if (idx >= items.size()) break;
                auto& it = items[idx++];
                if (st.IsObject() && st.HasMember("resting") && st["resting"].IsObject()) {
                    auto& rest = st["resting"];
                    if (rest.HasMember("oid") && rest["oid"].IsUint64()) {
                        std::lock_guard<std::mutex> g(it->m);
                        it->done = true; it->resp = {true, "ok", std::optional<std::string>(std::to_string(rest["oid"].GetUint64())), std::nullopt, std::optional<std::string>("accepted"), {}}; it->cv.notify_all();
                        continue;
                    }
                } else if (st.IsObject() && st.HasMember("filled") && st["filled"].IsObject()) {
                    auto& fil = st["filled"];
                    std::string oid_str;
                    if (fil.HasMember("oid") && fil["oid"].IsUint64()) oid_str = std::to_string(fil["oid"].GetUint64());
                    // Emit fill callback immediately
                    if (fill_cb_) {
                        FillData f{};
                        f.client_order_id = it->client_order_id.empty() ? it->cloid : it->client_order_id;
                        f.exchange_order_id = oid_str;
                        f.exec_id = oid_str; // no explicit exec id in immediate response; use oid placeholder
                        f.symbol = it->symbol;
                        f.side = it->is_buy ? "buy" : "sell";
                        if (fil.HasMember("avgPx") && fil["avgPx"].IsString()) f.price = fil["avgPx"].GetString();
                        if (fil.HasMember("totalSz") && fil["totalSz"].IsString()) f.quantity = fil["totalSz"].GetString();
                        f.fee = "0"; f.fee_currency = "USDC"; f.liquidity = "taker";
                        f.timestamp_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
                        // Provide extra context for downstream mapping
                        f.extra_data["side"] = f.side;
                        std::string parent_intent = parent_for_client_id(f.client_order_id);
                        if (!parent_intent.empty()) {
                            f.extra_data["child_id"] = f.client_order_id;
                            f.extra_data["intent"] = parent_intent;
                        } else {
                            f.extra_data["intent"] = f.client_order_id;
                        }
                        try { fill_cb_(f); } catch (...) {}
                        // Update last known fill price cache
                        try {
                            if (!f.symbol.empty() && !f.price.empty()) {
                                double pxv = std::stod(f.price);
                                std::lock_guard<std::mutex> lk(px_cache_mutex_);
                                last_fill_px_[f.symbol] = pxv;
                            }
                        } catch (...) {}
                    }
                    std::lock_guard<std::mutex> g(it->m);
                    it->done = true; it->resp = {true, "ok", (oid_str.empty()? std::nullopt : std::optional<std::string>(oid_str)), std::nullopt, std::optional<std::string>("filled"), {}}; it->cv.notify_all();
                    continue;
                }
                std::string why;
                if (st.IsObject()) {
                    if (st.HasMember("reason") && st["reason"].IsString()) why = st["reason"].GetString();
                    else if (st.HasMember("status") && st["status"].IsString()) why = st["status"].GetString();
                } else if (st.IsString()) {
                    why = st.GetString();
                }
                try { if (!why.empty()) spdlog::info("[HL] order status(reason): {}", why); } catch (...) {}
                std::lock_guard<std::mutex> g(it->m);
                it->done = true; it->resp = {false, why.empty() ? std::string("rejected") : why, std::nullopt, std::nullopt, std::nullopt, {}}; it->cv.notify_all();
            }
            // If fewer statuses returned, mark remaining as generic ok
            for (; idx < items.size(); ++idx) { auto& it = items[idx]; std::lock_guard<std::mutex> g(it->m); it->done = true; it->resp = {true, "ok", std::nullopt, std::nullopt, std::nullopt, {}}; it->cv.notify_all(); }
        } else {
            for (auto& it : items) { std::lock_guard<std::mutex> g(it->m); it->done = true; it->resp = {true, "ok", std::nullopt, std::nullopt, std::nullopt, {}}; it->cv.notify_all(); }
        }
    } else {
        for (auto& it : items) { std::lock_guard<std::mutex> g(it->m); it->done = true; it->resp = {true, "ok", std::nullopt, std::nullopt, std::nullopt, {}}; it->cv.notify_all(); }
    }
}

bool HyperliquidAdapter::send_signed_action_json(const std::string& payload_json, std::string& out_resp_json) {
    bool ok_send = false;
    const bool ws_available = (ws_post_ != nullptr);
    const bool ws_connected = (ws_available && ws_post_->is_connected());
    try {
        spdlog::info("[HL] send_signed_action_json: ws_available={} ws_connected={} disable_ws_post_={} payload_bytes={}",
                     (ws_available ? "yes" : "no"),
                     (ws_connected ? "yes" : "no"),
                     (disable_ws_post_ ? "yes" : "no"),
                     payload_json.size());
    } catch (...) {}
    // Choose transport order based on ws_first_ flag
    auto try_ws = [&]() {
        if (!(ws_post_ && ws_post_->is_connected())) return false;
        try {
            spdlog::info("[HL] ws action post attempt (timeout={} ms)", ws_post_timeout_ms_);
            auto resp = ws_post_->post("action", payload_json, std::chrono::milliseconds(ws_post_timeout_ms_));
            if (resp) {
                out_resp_json = *resp;
                try { spdlog::info("[HL] ws action post ok (bytes={})", out_resp_json.size()); } catch (...) {}
                return true;
            }
            if (ws_post_->is_connected()) {
                // Treat missing response as accepted to avoid blocking upstream; engine will correlate via private WS
                out_resp_json.clear();
                try { spdlog::warn("[HL] ws action post pending ack (no response within {} ms)", ws_post_timeout_ms_); } catch (...) {}
                return true;
            }
        } catch (const std::exception& e) {
            out_resp_json = e.what();
            try { spdlog::warn("[HL] ws action post error: {}", e.what()); } catch (...) {}
        } catch (...) {
            out_resp_json.clear();
            try { spdlog::warn("[HL] ws action post error: unknown exception"); } catch (...) {}
        }
        return false;
    };
    auto try_http = [&]() {
        try {
            auto parts = parse_base_url(cfg_.rest_base);
            latentspeed::nethttp::HttpClient httpc;
            std::vector<latentspeed::nethttp::Header> hdrs = {{"Content-Type","application/json"}};
            out_resp_json = httpc.request("POST", parts.scheme, parts.host, parts.port, "/exchange", hdrs, payload_json);
            try { spdlog::info("[HL] post via HTTP (bytes={})", out_resp_json.size()); } catch (...) {}
            return true;
        } catch (const std::exception& e) {
            out_resp_json = e.what();
            try { spdlog::warn("[HL] http action post error: {}", e.what()); } catch (...) {}
            return false;
        } catch (...) {
            out_resp_json.clear();
            try { spdlog::warn("[HL] http action post error: unknown"); } catch (...) {}
            return false;
        }
    };

    if (ws_first_) {
        ok_send = try_ws();
        if (!ok_send) ok_send = try_http();
    } else {
        ok_send = try_http();
        if (!ok_send) ok_send = try_ws();
    }
    return ok_send;
}

bool HyperliquidAdapter::try_reserve_request_weight(int weight) {
    try {
        rapidjson::Document action(rapidjson::kObjectType);
        auto& alloc = action.GetAllocator();
        action.AddMember("type", rapidjson::Value("reserveRequestWeight", alloc), alloc);
        action.AddMember("weight", rapidjson::Value(weight), alloc);
        rapidjson::StringBuffer sb; rapidjson::Writer<rapidjson::StringBuffer> wr(sb); action.Accept(wr);
        const uint64_t nonce = nonce_mgr_ ? nonce_mgr_->next() : 0;
        auto packed = signer_ ? signer_->build_action_payload(to_lower_ascii(api_secret_), sb.GetString(), vault_address_, nonce, !testnet_) : std::nullopt;
        if (!packed) return false;
        std::string resp;
        return send_signed_action_json(*packed, resp);
    } catch (...) { return false; }
}

std::optional<std::pair<double,double>> HyperliquidAdapter::fetch_top_of_book(const std::string& coin_upper) {
    try {
        auto parts = parse_base_url(cfg_.rest_base);
        latentspeed::nethttp::HttpClient httpc;
        std::vector<latentspeed::nethttp::Header> hdrs = {{"Content-Type","application/json"}};
        // Prefer l2Book info; request minimal significant figures
        rapidjson::Document req(rapidjson::kObjectType);
        auto& alloc = req.GetAllocator();
        req.AddMember("type", rapidjson::Value("l2Book", alloc), alloc);
        req.AddMember("coin", rapidjson::Value(coin_upper.c_str(), alloc), alloc);
        req.AddMember("nSigFigs", rapidjson::Value(5), alloc);
        req.AddMember("mantissa", rapidjson::Value(rapidjson::kNullType), alloc);
        rapidjson::StringBuffer sb; { rapidjson::Writer<rapidjson::StringBuffer> wr(sb); req.Accept(wr); }
        auto resp = httpc.request("POST", parts.scheme, parts.host, parts.port, "/info", hdrs, sb.GetString());
        rapidjson::Document d; d.Parse(resp.c_str());
        const rapidjson::Value* root = &d;
        if (d.HasMember("data") && d["data"].IsObject()) root = &d["data"];
        if (root->IsObject() && root->HasMember("levels") && (*root)["levels"].IsArray() && (*root)["levels"].Size() >= 2) {
            const auto& bids = (*root)["levels"][0];
            const auto& asks = (*root)["levels"][1];
            double bid = 0.0, ask = 0.0;
            if (bids.IsArray() && bids.Size() > 0 && bids[0].IsArray() && bids[0].Size() > 0) {
                const auto& l = bids[0][0]; if (l.IsObject() && l.HasMember("px") && l["px"].IsString()) bid = std::stod(l["px"].GetString());
            }
            if (asks.IsArray() && asks.Size() > 0 && asks[0].IsArray() && asks[0].Size() > 0) {
                const auto& l = asks[0][0]; if (l.IsObject() && l.HasMember("px") && l["px"].IsString()) ask = std::stod(l["px"].GetString());
            }
            if (bid > 0.0 || ask > 0.0) return std::make_optional(std::make_pair(bid, ask));
        }
    } catch (...) {}
    return std::nullopt;
}

// keep namespace open for helper methods below
void HyperliquidAdapter::confirm_resting_async(const std::string& symbol,
                                               const std::string& client_order_id,
                                               const std::string& exchange_order_id,
                                               const std::string& cloid_hex) {
    // Background confirm using /info orderStatus (by oid if available, else by cloid).
    std::thread([this, symbol, client_order_id, exchange_order_id, cloid_hex](){
        try {
            const std::string user = util::to_lower_hex_address(api_key_);
            auto parts = parse_base_url(cfg_.rest_base);
            latentspeed::nethttp::HttpClient httpc;
            std::vector<latentspeed::nethttp::Header> hdrs = {{"Content-Type","application/json"}};
            // Prefer oid when numeric; else try mapped HL cloid
            unsigned long long oid_num = 0ULL; bool have_oid=false;
            try {
                if (!exchange_order_id.empty()) { oid_num = std::stoull(exchange_order_id); have_oid = true; }
            } catch (...) { have_oid=false; }
            std::string hl_cloid = cloid_hex;
            if (hl_cloid.empty() || !is_valid_cloid(hl_cloid)) {
                std::lock_guard<std::mutex> lk(cloid_map_mutex_);
                auto it = clientid_to_cloid_.find(to_lower_ascii(client_order_id));
                if (it != clientid_to_cloid_.end()) hl_cloid = it->second;
            }
            for (int attempt = 0; attempt < 3; ++attempt) {
                bool should_retry = true;
                try {
                    rapidjson::Document req(rapidjson::kObjectType);
                    auto& alloc = req.GetAllocator();
                    req.AddMember("type", rapidjson::Value("orderStatus", alloc), alloc);
                    req.AddMember("user", rapidjson::Value(user.c_str(), alloc), alloc);
                    if (have_oid) {
                        req.AddMember("oid", rapidjson::Value(static_cast<uint64_t>(oid_num)), alloc);
                    } else if (is_valid_cloid(hl_cloid)) {
                        req.AddMember("oid", rapidjson::Value(hl_cloid.c_str(), alloc), alloc);
                    } else {
                        should_retry = false;
                    }
                    if (!should_retry) {
                        break;
                    }
                    rapidjson::StringBuffer sb; { rapidjson::Writer<rapidjson::StringBuffer> wr(sb); req.Accept(wr); }
                    auto resp = httpc.request("POST", parts.scheme, parts.host, parts.port, "/info", hdrs, sb.GetString());
                    rapidjson::Document d; d.Parse(resp.c_str());
                    if (!d.HasParseError() && d.IsObject() && !d.ObjectEmpty()) {
                        const rapidjson::Value* root = &d;
                        if (d.HasMember("payload") && d["payload"].IsObject()) root = &d["payload"];
                        if (root->IsObject() && root->HasMember("response") && (*root)["response"].IsObject()) root = &(*root)["response"];
                        if (root->IsObject() && root->HasMember("data") && (*root)["data"].IsObject()) root = &(*root)["data"];
                        const rapidjson::Value* order_node = nullptr;
                        if (root->IsObject() && root->HasMember("order") && (*root)["order"].IsObject()) {
                            order_node = &(*root)["order"];
                        }
                        if (order_node) {
                            std::string hl_status;
                            if (order_node->HasMember("status") && (*order_node)["status"].IsString()) {
                                hl_status = (*order_node)["status"].GetString();
                            }
                            if (order_node->HasMember("order")) {
                                if ((*order_node)["order"].IsNull()) {
                                    should_retry = false;
                                } else if ((*order_node)["order"].IsObject()) {
                                    const auto& order_obj = (*order_node)["order"];
                                    std::string mapped_oid = exchange_order_id;
                                    if (order_obj.HasMember("oid") && (order_obj["oid"].IsUint64() || order_obj["oid"].IsInt64())) {
                                        mapped_oid = std::to_string(order_obj["oid"].GetUint64());
                                        have_oid = true;
                                        oid_num = static_cast<unsigned long long>(order_obj["oid"].GetUint64());
                                    }
                                    if (order_obj.HasMember("cloid") && order_obj["cloid"].IsString()) {
                                        std::string resp_cloid = order_obj["cloid"].GetString();
                                        if (!resp_cloid.empty()) {
                                            remember_cloid_mapping(resp_cloid, client_order_id);
                                            hl_cloid = resp_cloid;
                                        }
                                    }
                                    std::string role;
                                    if (order_obj.HasMember("trigger") && order_obj["trigger"].IsObject()) {
                                        const auto& trig = order_obj["trigger"];
                                        if (trig.HasMember("tpsl") && trig["tpsl"].IsString()) role = trig["tpsl"].GetString();
                                    }
                                    if (!mapped_oid.empty()) {
                                        remember_oid_clientid(mapped_oid, client_order_id);
                                        if (!role.empty()) remember_oid_role(mapped_oid, role);
                                        if (order_update_cb_) {
                                            OrderUpdate upd{};
                                            upd.client_order_id = client_order_id;
                                            upd.exchange_order_id = mapped_oid;
                                            if (!hl_status.empty()) {
                                                std::string lower = to_lower_ascii(hl_status);
                                                if (lower == "open") upd.status = "new";
                                                else if (lower == "triggered" || lower == "accepted" || lower == "frontendsubmitted") upd.status = "accepted";
                                                else if (lower == "filled") upd.status = "filled";
                                                else if (lower == "canceled" || lower == "cancelled" || lower == "margincanceled" || lower == "scheduledcancel" || lower == "nonusercancel") upd.status = "canceled";
                                                else if (lower == "rejected" || lower.find("rejected") != std::string::npos) upd.status = "rejected";
                                                else upd.status = hl_status;
                                            } else {
                                                upd.status = "new";
                                            }
                                            upd.timestamp_ms = now_ms_();
                                            try { order_update_cb_(upd); } catch (...) {}
                                        }
                                        return;
                                    }
                                }
                            }
                        }
                    }
                } catch (...) {
                    // leave should_retry as true to retry on transient errors
                }
                if (!should_retry) {
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(4000));
            }
        } catch (...) {}
    }).detach();
}

std::string HyperliquidAdapter::ensure_hl_cloid(const std::string& maybe_id) {
    if (is_valid_cloid(maybe_id)) return std::string(maybe_id);
    // Generate a random 16-byte hex id
    std::random_device rd;
    std::mt19937_64 gen(rd());
    uint64_t hi = gen();
    uint64_t lo = gen();
    std::ostringstream oss;
    oss << "0x" << std::hex << std::nouppercase << std::setfill('0') << std::setw(16) << hi << std::setw(16) << lo;
    return oss.str();
}

void HyperliquidAdapter::remember_cloid_mapping(const std::string& hl_cloid, const std::string& original_id) {
    if (hl_cloid.empty() || original_id.empty()) return;
    std::lock_guard<std::mutex> lk(cloid_map_mutex_);
    const std::string hlc_l = to_lower_ascii(hl_cloid);
    const std::string orig_l = to_lower_ascii(original_id);
    cloid_to_clientid_[hlc_l] = original_id;
    clientid_to_cloid_[orig_l] = hlc_l;
}

std::string HyperliquidAdapter::map_back_client_id(const std::string& hl_cloid) {
    if (hl_cloid.empty()) return std::string();
    std::lock_guard<std::mutex> lk(cloid_map_mutex_);
    auto it = cloid_to_clientid_.find(to_lower_ascii(hl_cloid));
    if (it != cloid_to_clientid_.end()) return it->second;
    return hl_cloid;
}

void HyperliquidAdapter::remember_cloid_role(const std::string& hl_cloid, const std::string& role) {
    if (hl_cloid.empty() || role.empty()) return;
    std::lock_guard<std::mutex> lk(cloid_map_mutex_);
    cloid_to_role_[to_lower_ascii(hl_cloid)] = to_lower_ascii(role);
}

void HyperliquidAdapter::remember_oid_clientid(const std::string& oid, const std::string& client_id) {
    if (oid.empty() || client_id.empty()) return;
    std::lock_guard<std::mutex> lk(cloid_map_mutex_);
    oid_to_clientid_[oid] = client_id;
}

void HyperliquidAdapter::remember_oid_role(const std::string& oid, const std::string& role) {
    if (oid.empty() || role.empty()) return;
    std::lock_guard<std::mutex> lk(cloid_map_mutex_);
    oid_to_role_[oid] = to_lower_ascii(role);
}

void HyperliquidAdapter::register_parent_intent(const std::string& client_order_id, const std::string& intent_id) {
    if (client_order_id.empty() || intent_id.empty()) return;
    std::lock_guard<std::mutex> lk(cloid_map_mutex_);
    child_to_parent_[to_lower_ascii(client_order_id)] = intent_id;
}

void HyperliquidAdapter::remember_child_parent(const std::string& child_client_id,
                                               const std::string& parent_client_id) {
    if (child_client_id.empty() || parent_client_id.empty()) return;
    std::lock_guard<std::mutex> lk(cloid_map_mutex_);
    std::string resolved_parent = parent_client_id;
    auto it = child_to_parent_.find(to_lower_ascii(parent_client_id));
    if (it != child_to_parent_.end() && !it->second.empty()) {
        resolved_parent = it->second;
    }
    child_to_parent_[to_lower_ascii(child_client_id)] = resolved_parent;
}

void HyperliquidAdapter::maybe_trigger_event_driven_reconnect_(const char* from_tag) {
    if (!enable_proactive_reconnect_) return;

    const uint64_t armed = last_order_placement_ms_.load(std::memory_order_acquire);
    if (armed == 0) return;

    const uint64_t seen_fill  = recon_last_seen_fill_ms_.load(std::memory_order_acquire);
    const uint64_t seen_upd   = recon_last_seen_update_ms_.load(std::memory_order_acquire);

    // Require BOTH signals to be newer than the last placement
    if (seen_fill >= armed && seen_upd >= armed) {
        // Optional: avoid closing during an active burst
        const uint64_t now  = now_ms_();
        const uint64_t last = last_private_event_ms_.load(std::memory_order_relaxed);
        if (last && now > last && (now - last) < 30) {
            return; // wait for a >30ms quiet gap
        }

        // Disarm and close ws_subscribe_ (async) to force a clean resubscribe path
        last_order_placement_ms_.store(0, std::memory_order_release);

        try {
            spdlog::warn("[HL-WS] proactive reconnect: fill+update both seen after placement (armed={} fillΔ={}ms updΔ={}ms) source={}",
                         armed,
                         (long long)(seen_fill - armed),
                         (long long)(seen_upd - armed),
                         (from_tag ? from_tag : "unknown"));
        } catch (...) {}

        std::thread([this](){
            // tiny grace to allow trailing frames to arrive
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
            {
                std::lock_guard<std::mutex> lk(ws_subscribe_mutex_);
                if (ws_subscribe_) {
                    try { spdlog::info("[HL-WS] closing ws_subscribe for proactive reconnect"); } catch (...) {}
                    ws_subscribe_->close();
                }
            }
        }).detach();
    }
}


std::string HyperliquidAdapter::parent_for_client_id(const std::string& client_id) {
    if (client_id.empty()) return std::string();
    std::lock_guard<std::mutex> lk(cloid_map_mutex_);
    auto it = child_to_parent_.find(to_lower_ascii(client_id));
    if (it != child_to_parent_.end()) return it->second;
    return std::string();
}

} // namespace latentspeed
