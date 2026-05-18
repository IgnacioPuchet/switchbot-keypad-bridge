#pragma once

#include <NimBLEDevice.h>
#include <psa/crypto.h>

#include <array>
#include <cstdint>
#include <functional>
#include <string>

#include "esphome/components/event/event.h"
#include "esphome/components/text_sensor/text_sensor.h"
#include "esphome/core/automation.h"
#include "esphome/core/component.h"
#include "esphome/core/defines.h"
#include "esphome/core/helpers.h"

// NimBLE's log_common.h defines LOG_LEVEL_* as plain macros, which collide
// with identically-named members of ESPHome enums included downstream.
// ESPHome uses ESPHOME_LOG_LEVEL_* for its own logging, so these undefs are safe.
#undef LOG_LEVEL_NONE
#undef LOG_LEVEL_ERROR
#undef LOG_LEVEL_WARN
#undef LOG_LEVEL_INFO
#undef LOG_LEVEL_DEBUG
#undef LOG_LEVEL_CRITICAL

namespace esphome {
namespace switchbot_keypad_bridge {

enum class UnlockMethod : uint8_t {
  UNKNOWN = 0x00,
  PIN = 0x04,
  FINGERPRINT = 0x0C,
};

const char *unlock_method_name(UnlockMethod method);

class SwitchbotKeypadBridge : public Component {
  SUB_TEXT_SENSOR(ble_mac)

 public:
  void setup() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

  void set_shared_key(const std::string &key) { this->shared_key_hex_ = key; }
  void set_keypad_event(event::Event *ev) { this->keypad_event_ = ev; }

  void add_on_lock_callback(std::function<void()> &&callback) {
    this->on_lock_callbacks_.add(std::move(callback));
  }
  void add_on_unlock_callback(std::function<void(std::string, int)> &&callback) {
    this->on_unlock_callbacks_.add(std::move(callback));
  }

 protected:
  class ServerCallbacks;
  class RxCharCallbacks;
  friend class ServerCallbacks;
  friend class RxCharCallbacks;

  enum class LockState : uint8_t {
    LOCKED = 0x81,
    UNLOCKED = 0x91,
  };

  enum class CommandType : uint8_t {
    UNKNOWN,
    LOCK,
    UNLOCK,
    STATE_POLL,
  };

  // 4-byte transport header echoed back on every encrypted exchange.
  struct FrameHeader {
    uint8_t key_id;
    uint8_t seq_a;
    uint8_t seq_b;
  };

  struct DecodedCommand {
    CommandType type{CommandType::UNKNOWN};
    UnlockMethod method{UnlockMethod::UNKNOWN};
    int16_t credential_index{-1};
  };

  // ----- Configuration / setup -----------------------------------------------

  bool prepare_keys_();
  bool prepare_ble_();

  // ----- BLE write handling --------------------------------------------------

  void on_rx_frame_(const std::string &frame);
  bool is_session_iv_request_(const std::string &frame) const;
  void send_session_iv_();

  bool decode_command_(const uint8_t *plaintext, size_t length, DecodedCommand &out) const;
  void handle_command_(const FrameHeader &header, const DecodedCommand &command);
  void handle_state_poll_(const FrameHeader &header);

  // ----- Transport helpers ---------------------------------------------------

  void send_ack_(const FrameHeader &header);
  void send_encrypted_response_(const FrameHeader &header, const uint8_t *plaintext, size_t length);
  void notify_(const uint8_t *data, size_t length);

  // ----- Crypto (AES-CTR is symmetric, so a single primitive covers both ways) -

  bool aes_ctr_xcrypt_(const uint8_t *input, size_t length, uint8_t *output);
  void rotate_session_iv_();

  // ----- Anti-replay ---------------------------------------------------------

  void reset_session_state_();
  void clear_replay_history_();
  bool is_replayed_ciphertext_(const uint8_t *ciphertext, size_t length) const;
  void record_ciphertext_(const uint8_t *ciphertext, size_t length);

  // ----- Eventing ------------------------------------------------------------

  void publish_lock_();
  void publish_unlock_(UnlockMethod method, int index);

  // ----- BLE handles ---------------------------------------------------------

  NimBLEServer *server_{nullptr};
  NimBLECharacteristic *tx_characteristic_{nullptr};

  // ----- ESPHome wiring ------------------------------------------------------

  event::Event *keypad_event_{nullptr};
  CallbackManager<void()> on_lock_callbacks_{};
  CallbackManager<void(std::string, int)> on_unlock_callbacks_{};

  // ----- User configuration --------------------------------------------------

  std::string shared_key_hex_;

  // ----- Runtime state -------------------------------------------------------

  // PSA AES-CTR key handle. Imported once at setup so the per-frame crypto
  // path does not pay the cost (or risk the failure) of re-importing it.
  psa_key_id_t aes_key_handle_{PSA_KEY_ID_NULL};
  LockState lock_state_{LockState::LOCKED};

  // 20-byte session IV response: [0x01, 0x00, 0x00, 0x00, IV(16)].
  // The trailing 16 bytes are also used as the AES-CTR IV for the live session.
  std::array<uint8_t, 20> session_iv_response_{0x01, 0x00, 0x00, 0x00};

  // Per-session anti-replay state. Reset on connect, disconnect, and on
  // every IV re-negotiation.
  static constexpr size_t REPLAY_HISTORY_SIZE = 8;
  static constexpr size_t MAX_REPLAY_PAYLOAD = 32;
  struct ReplayEntry {
    std::array<uint8_t, MAX_REPLAY_PAYLOAD> data{};
    size_t length{0};
  };
  std::array<ReplayEntry, REPLAY_HISTORY_SIZE> replay_history_{};
  size_t replay_head_{0};
  bool iv_established_{false};
};

}  // namespace switchbot_keypad_bridge
}  // namespace esphome
