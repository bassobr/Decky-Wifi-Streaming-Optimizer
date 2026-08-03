import { useEffect, useState } from "react";
import { PanelSection, PanelSectionRow, ToggleField, TextField } from "@decky/ui";
import type { PluginStatus, StreamingApp } from "../types";
import { InfoRow } from "./InfoRow";
import * as backend from "../backend";
import { theme } from "../theme";

interface StreamingSectionProps {
  status: PluginStatus;
  isBusy: boolean;
  error?: string;
  onToggleMode: (val: boolean) => void;
  onToggleApp: (appId: string, val: boolean) => void;
  onSavePatterns: (patterns: string) => void;
}

// "Streaming auto mode" panel: master toggle plus the per-app detection list.
// While the mode is on, the volatile fixes (power save/ASPM, buffer tuning,
// CAKE) are only held active while one of the enabled apps below is running;
// the rest of the time the system stays on stock settings to save battery.
export function StreamingSection({
  status,
  isBusy,
  error,
  onToggleMode,
  onToggleApp,
  onSavePatterns,
}: StreamingSectionProps) {
  const s = status.settings;
  const enabled = s?.streaming_mode_enabled ?? false;
  const active = status.live?.streaming_active ?? false;
  const detectedApp = status.live?.streaming_detected_app ?? "";

  // Preset catalog is static per plugin version; fetch once.
  const [apps, setApps] = useState<StreamingApp[]>([]);
  const [patternsInput, setPatternsInput] = useState(
    s?.streaming_custom_patterns ?? "",
  );

  useEffect(() => {
    backend
      .getStreamingApps()
      .then((r) => setApps(r.apps ?? []))
      .catch(() => {});
  }, []);

  return (
    <PanelSection title="Streaming auto mode">
      <InfoRow
        label="Only fix while streaming"
        subtitle={
          enabled
            ? "Fixes apply automatically while a streaming app runs"
            : "Off: enabled fixes apply all the time"
        }
        explanation="Watches for the streaming apps selected below. When one starts, the lag-spike fixes you've enabled (power save, buffer tuning, CAKE) are applied automatically; when it exits, the system returns to stock settings. This keeps the battery savings of WiFi power management outside of streaming sessions. Settings that reconnect WiFi (BSSID lock, band, DNS, IPv6) stay global and are not touched mid-session."
        checked={enabled}
        disabled={isBusy}
        error={error}
        onChange={onToggleMode}
      />
      {enabled && (
        <>
          <PanelSectionRow>
            <div
              style={{
                fontSize: theme.fontSize.small,
                color: active ? theme.success.text : theme.text.tertiary,
                padding: "2px 0",
              }}
            >
              {active
                ? `● Streaming detected: ${detectedApp}`
                : "○ No streaming app running - stock settings"}
            </div>
          </PanelSectionRow>
          {apps.map((app) => (
            <PanelSectionRow key={app.id}>
              <ToggleField
                label={
                  <span style={{ fontSize: theme.fontSize.body }}>{app.label}</span>
                }
                checked={s?.streaming_apps?.[app.id] ?? true}
                disabled={isBusy}
                onChange={(val: boolean) => onToggleApp(app.id, val)}
              />
            </PanelSectionRow>
          ))}
          <PanelSectionRow>
            <TextField
              label="Custom process patterns (space-separated)"
              value={patternsInput}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setPatternsInput(e.target.value)
              }
              onBlur={() => onSavePatterns(patternsInput)}
            />
          </PanelSectionRow>
        </>
      )}
    </PanelSection>
  );
}
