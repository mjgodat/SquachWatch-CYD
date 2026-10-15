// SquachWatch-CYD — Bruce Toolbox UI
// Draws the offensive-tools menu inside SquatchWatch's visual shell.
// Each tool is a stub right now; the implementations will come from
// Bruce's modules, adapted to draw through SquatchWatch's TFT_eSPI.
#include "ui_toolbox.h"
#include "theme.h"
#include "settings.h"
#include <Arduino.h>

// ---- State ----

static ToolboxLevel  s_level  = ToolboxLevel::CATEGORIES;
static int           s_scroll = 0;
static int           s_selected = -1;   // highlighted row, -1 = none
static bool          s_toolActive = false;

// ---- Layout constants ----

static const int ROW_H     = 42;
static const int ROW_PAD   = 6;
static const int HEADER_H  = 36;
static const int TEXT_Y_OFF = 12;  // text baseline offset within a row

// ---- Menu labels ----

static const char* CAT_LABELS[] = {
    "\xF0\x9F\x93\xA1 WIFI ATTACKS",    // will render as text, emoji stripped on TFT
    "\xF0\x9F\x93\xB1 BLE TOOLS",
    "\xF0\x9F\x94\x8C USB / BADUSB",
    "\xF0\x9F\x94\xA7 UTILITIES",
    "\xE2\x86\x90 BACK"
};
// Plain ASCII fallback labels (what actually renders on TFT_eSPI)
static const char* CAT_LABELS_PLAIN[] = {
    "WIFI ATTACKS",
    "BLE TOOLS",
    "USB / BADUSB",
    "UTILITIES",
    "< BACK"
};

static const char* WIFI_LABELS[] = {
    "SCAN NETWORKS",
    "DEAUTH",
    "BEACON SPAM",
    "EVIL PORTAL",
    "PROBE SNIFF",
    "PMKID CAPTURE",
    "HANDSHAKE CAPTURE",
    "PCAP TO SD",
    "DHCP STARVE",
    "AP CLONE",
    "KARMA",
    "RICKROLL",
    "< BACK"
};

static const char* BLE_LABELS[] = {
    "SCAN DEVICES",
    "APPLE SPAM",
    "SAMSUNG SPAM",
    "SWIFTPAIR SPAM",
    "AIRTAG SPOOF",
    "FLIPPER DETECT",
    "BLE ENUMERATE",
    "< BACK"
};

static const char* USB_LABELS[] = {
    "DUCKY SCRIPT (SD)",
    "KEYSTROKE INJECT",
    "USB KEYBOARD",
    "USB STORAGE",
    "< BACK"
};

static const char* UTIL_LABELS[] = {
    "SD BROWSER",
    "WIFI LOGGER",
    "PCAP VIEWER",
    "< BACK"
};

// ---- Helpers ----

static const char** labelsForLevel(ToolboxLevel lvl, int& count) {
    switch (lvl) {
        case ToolboxLevel::CATEGORIES: count = (int)ToolCategory::COUNT;  return CAT_LABELS_PLAIN;
        case ToolboxLevel::WIFI_TOOLS: count = (int)WifiTool::COUNT;     return WIFI_LABELS;
        case ToolboxLevel::BLE_TOOLS:  count = (int)BleTool::COUNT;      return BLE_LABELS;
        case ToolboxLevel::USB_TOOLS:  count = (int)UsbTool::COUNT;      return USB_LABELS;
        case ToolboxLevel::UTIL_TOOLS: count = (int)UtilTool::COUNT;     return UTIL_LABELS;
        default: count = 0; return nullptr;
    }
}

static const char* headerForLevel(ToolboxLevel lvl) {
    switch (lvl) {
        case ToolboxLevel::CATEGORIES: return "TOOLBOX";
        case ToolboxLevel::WIFI_TOOLS: return "WIFI ATTACKS";
        case ToolboxLevel::BLE_TOOLS:  return "BLE TOOLS";
        case ToolboxLevel::USB_TOOLS:  return "USB / BADUSB";
        case ToolboxLevel::UTIL_TOOLS: return "UTILITIES";
        case ToolboxLevel::TOOL_RUNNING: return "RUNNING...";
        default: return "TOOLBOX";
    }
}

// ---- Draw ----

static void drawRow(TFT_eSPI& t, int x, int y, int w, const char* label, bool highlight) {
    const uint16_t bg = highlight ? Theme::PURPLE : Theme::TASKBAR;
    const uint16_t fg = highlight ? Theme::BG     : Theme::CYAN;
    t.fillRoundRect(x, y, w, ROW_H - 4, 6, bg);
    t.setTextColor(fg, bg);
    t.setTextSize(1);
    t.setTextDatum(ML_DATUM);
    t.drawString(label, x + 14, y + ROW_H / 2 - 2, 2);
}

void uiToolboxInit(TFT_eSPI& t) {
    s_level = ToolboxLevel::CATEGORIES;
    s_scroll = 0;
    s_selected = -1;
    s_toolActive = false;
}

void uiToolboxTick(TFT_eSPI& t, uint32_t now) {
    const int w = t.width();
    const int h = t.height();

    // Background — solid theme color (no DetectionEngine dependency here)
    t.fillRect(0, 0, w, h, Theme::BG);

    // Header bar
    t.fillRect(0, 0, w, HEADER_H, Theme::TASKBAR);
    t.setTextColor(Theme::VAPOR_PINK, Theme::TASKBAR);
    t.setTextSize(1);
    t.setTextDatum(MC_DATUM);
    t.drawString(headerForLevel(s_level), w / 2, HEADER_H / 2, 4);

    if (s_level == ToolboxLevel::TOOL_RUNNING) {
        // Tool is running — show a simple status
        t.setTextColor(Theme::CYAN, Theme::BG);
        t.setTextDatum(MC_DATUM);
        t.drawString("Tool active...", w / 2, h / 2, 4);
        t.drawString("TAP TO STOP", w / 2, h / 2 + 30, 2);
        return;
    }

    // Menu rows
    int count = 0;
    const char** labels = labelsForLevel(s_level, count);
    if (!labels) return;

    const int menuTop = HEADER_H + ROW_PAD;
    const int visibleRows = (h - menuTop) / (ROW_H + ROW_PAD);

    for (int i = 0; i < count; i++) {
        const int y = menuTop + (i - s_scroll) * (ROW_H + ROW_PAD);
        if (y < HEADER_H - ROW_H || y > h) continue;  // off screen
        const bool isBack = (i == count - 1);
        const bool hl = (i == s_selected);
        drawRow(t, ROW_PAD, y, w - ROW_PAD * 2, labels[i], hl);

        // Back row gets a different accent
        if (isBack) {
            t.fillRoundRect(ROW_PAD, y, w - ROW_PAD * 2, ROW_H - 4, 6, Theme::BG);
            t.setTextColor(Theme::AMBER, Theme::BG);
            t.setTextDatum(ML_DATUM);
            t.drawString(labels[i], ROW_PAD + 14, y + ROW_H / 2 - 2, 2);
        }
    }
}

void uiToolboxScroll(int delta) {
    int count = 0;
    labelsForLevel(s_level, count);
    s_scroll += delta;
    if (s_scroll < 0) s_scroll = 0;
    if (s_scroll > count - 3) s_scroll = count - 3;
    if (s_scroll < 0) s_scroll = 0;
}

// ---- Tool stubs ----
// These will be replaced with actual Bruce tool implementations.

static void stubToolRun(const char* name) {
    Serial.printf("[toolbox] STUB: %s — not yet implemented\n", name);
    s_toolActive = true;
    s_level = ToolboxLevel::TOOL_RUNNING;
}

static void handleCategoryTap(int idx) {
    switch ((ToolCategory)idx) {
        case ToolCategory::WIFI: s_level = ToolboxLevel::WIFI_TOOLS; s_scroll = 0; break;
        case ToolCategory::BLE:  s_level = ToolboxLevel::BLE_TOOLS;  s_scroll = 0; break;
        case ToolCategory::USB:  s_level = ToolboxLevel::USB_TOOLS;  s_scroll = 0; break;
        case ToolCategory::UTIL: s_level = ToolboxLevel::UTIL_TOOLS; s_scroll = 0; break;
        case ToolCategory::BACK: break;  // caller handles return to CLEAR
        default: break;
    }
}

static bool handleWifiTap(int idx) {
    if ((WifiTool)idx == WifiTool::BACK) { s_level = ToolboxLevel::CATEGORIES; s_scroll = 0; return true; }
    stubToolRun(WIFI_LABELS[idx]);
    return true;
}

static bool handleBleTap(int idx) {
    if ((BleTool)idx == BleTool::BACK) { s_level = ToolboxLevel::CATEGORIES; s_scroll = 0; return true; }
    stubToolRun(BLE_LABELS[idx]);
    return true;
}

static bool handleUsbTap(int idx) {
    if ((UsbTool)idx == UsbTool::BACK) { s_level = ToolboxLevel::CATEGORIES; s_scroll = 0; return true; }
    stubToolRun(USB_LABELS[idx]);
    return true;
}

static bool handleUtilTap(int idx) {
    if ((UtilTool)idx == UtilTool::BACK) { s_level = ToolboxLevel::CATEGORIES; s_scroll = 0; return true; }
    stubToolRun(UTIL_LABELS[idx]);
    return true;
}

// ---- Public API ----

bool uiToolboxHandleTap(TFT_eSPI& t, int16_t x, int16_t y, uint32_t now) {
    // If a tool is running, any tap stops it
    if (s_level == ToolboxLevel::TOOL_RUNNING) {
        uiToolboxStopTool();
        return true;
    }

    const int menuTop = HEADER_H + ROW_PAD;
    if (y < menuTop) return true;  // tapped header, ignore

    int count = 0;
    labelsForLevel(s_level, count);

    const int row = (y - menuTop) / (ROW_H + ROW_PAD) + s_scroll;
    if (row < 0 || row >= count) return true;

    s_selected = row;

    switch (s_level) {
        case ToolboxLevel::CATEGORIES:
            if ((ToolCategory)row == ToolCategory::BACK) return false;  // exit toolbox
            handleCategoryTap(row);
            return true;
        case ToolboxLevel::WIFI_TOOLS: return handleWifiTap(row);
        case ToolboxLevel::BLE_TOOLS:  return handleBleTap(row);
        case ToolboxLevel::USB_TOOLS:  return handleUsbTap(row);
        case ToolboxLevel::UTIL_TOOLS: return handleUtilTap(row);
        default: return true;
    }
}

bool uiToolboxToolRunning() { return s_toolActive; }

void uiToolboxStopTool() {
    if (s_toolActive) {
        Serial.println("[toolbox] stopping active tool");
        // TODO: actual cleanup — stop WiFi promiscuous mode, BLE advertising, etc.
        s_toolActive = false;
    }
    s_level = ToolboxLevel::CATEGORIES;
    s_scroll = 0;
    s_selected = -1;
}
