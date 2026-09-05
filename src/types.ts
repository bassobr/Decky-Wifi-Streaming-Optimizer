export interface PluginSettings {
  model: string;
  driver: string;
  device_family: string;
  device_label: string;
  chip_label: string;
  supports_6ghz: boolean;
  power_save_disabled: boolean;
  auto_fix_on_wake: boolean;
  bssid_lock_enabled: boolean;
  bssid_lock_value: string;
  bssid_lock_connection_uuid: string;
  band_preference: string;
  band_preference_enabled: boolean;
  dns_provider: string;
  dns_servers: string;
  dns_enabled: boolean;
  ipv6_disabled: boolean;
  buffer_tuning_enabled: boolean;
  cake_enabled: boolean;
  streaming_mode_enabled: boolean;
  streaming_apps: Record<string, boolean>;
  streaming_custom_patterns: string;
  streaming_active: boolean;
  streaming_detected_app: string;
  distro_id: string;
  distro_name: string;
  last_connection_uuid: string;
  priority_set: boolean;
  update_channel: string;
  last_applied: number;
}

export interface LiveStatus {
  power_save_off?: boolean;
  signal_dbm?: string;
  tx_bitrate?: string;
  frequency?: string;
  channel?: string;
  ip_address?: string;
  buffer_tuning_applied?: boolean;
  cake_applied?: boolean;
  dispatcher_installed?: boolean;
  last_enforced?: number;
  wifi_backend?: string;
  backend_tool_available?: boolean;
  streaming_active?: boolean;
  streaming_detected_app?: string;
}

export interface StreamingApp {
  id: string;
  label: string;
}

export interface StreamingAppsResult {
  success: boolean;
  apps: StreamingApp[];
}

export interface PluginStatus {
  success: boolean;
  connected: boolean;
  support_tier: number;
  version?: string;
  settings: PluginSettings;
  live: LiveStatus;
  drift: Record<string, boolean>;
  last_applied?: number;
  error?: string;
  message?: string;
}

export interface MethodResult {
  success: boolean;
  error?: string;
  message?: string;
  detail?: string;
  reconnected?: boolean;
  [key: string]: unknown;
}

export interface OptimizeSafeResult extends MethodResult {
  total: number;
  applied: number;
  results: Record<string, MethodResult>;
}

export type BackendSwitchPhase =
  | "idle"
  | "switching"
  | "reconnecting"
  | "done"
  | "failed";

export interface BackendSwitchResult {
  success: boolean;
  backend?: string | null;
  target: string;
  recovery_performed?: boolean;
  needs_reboot?: boolean;
  reconnect_timed_out?: boolean;
  message?: string;
  detail?: string;
}

export interface BackendSwitchStatus {
  success: boolean;
  in_progress: boolean;
  phase: BackendSwitchPhase;
  target: string | null;
  started_at: number;
  result: BackendSwitchResult | null;
  message?: string;
}

export interface BackendSwitchStartResult {
  accepted: boolean;
  reason?: string;
  message?: string;
  target?: string;
  from?: string | null;
  backend?: string;
}

export interface UpdateCheckResult {
  success: boolean;
  current_version?: string;
  latest_version?: string;
  update_available?: boolean;
  channel?: string;
  release_url?: string;
  error?: string;
  message?: string;
}

export type BadgeStatus = "active" | "drifted" | "off" | "error" | "unknown";

// Keys mirror the error codes main.py actually returns.
export const ERROR_MESSAGES: Record<string, string> = {
  no_wifi: "Not connected to WiFi. Connect first, then optimize.",
  iw_failed: "Couldn't change WiFi setting. Try toggling WiFi off/on.",
  nmcli_failed: "Couldn't update connection. Forget and reconnect to this network.",
  write_failed: "Couldn't install auto-fix script. The filesystem may be locked.",
  invalid_pattern: "Custom patterns need at least 3 characters each.",
  unexpected: "Something went wrong. Check the Decky log for details.",
};
