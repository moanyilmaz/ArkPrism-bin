#!/usr/bin/env python3
"""
Expand native_privacy_apis.json to match privacy_apis.json coverage.

Uses explicit symbol naming based on OpenHarmony NDK conventions:
- OH_{Module}_{Operation} pattern (verified from existing entries)
- Adds dataDirection field to each entry for declarative direction
- Preserves existing entries, only adds missing ones
"""

import json
import sys
import os
from pathlib import Path

# ==========================================================
# Mapping: profilingCategory → Native API category + apiPackage prefix
# ==========================================================

CATEGORY_MAP = {
    # Already in native file (will be skipped)
    "device_identity.hardware": ("device_info", "OpenHarmony.Native.DeviceInfo"),
    "device_identity.software": ("device_info", "OpenHarmony.Native.DeviceInfo"),
    "device_identity.unique_id": ("device_identifier", "OpenHarmony.Native.DeviceIdentifier"),
    "location": ("location", "OpenHarmony.Native.Location"),
    "media.audio": ("audio_record", "OpenHarmony.Native.Audio"),
    "media.camera": ("camera", "OpenHarmony.Native.Camera"),
    "device_status.sensor": ("sensor", "OpenHarmony.Native.Sensor"),
    "network.connectivity": ("network_info", "OpenHarmony.Native.Network"),
    "user_data.clipboard": ("pasteboard", "OpenHarmony.Native.Pasteboard"),
    "native.dynamic_loading": ("dynamic_loading", "Native.LibDL"),
    "native.dynamic_symbol_resolution": ("dynamic_symbol_resolution", "Native.LibDL"),
    "native.command_execution": ("command_execution", "Native.LibC"),

    # Missing categories to add
    "device_identity.ad_tracking": ("device_identifier", "OpenHarmony.Native.DeviceIdentifier"),
    "device_identity.sim": ("sim", "OpenHarmony.Native.Sim"),
    "device_identity.mac": ("wifi_info", "OpenHarmony.Native.Wifi"),
    "user_data.account": ("account", "OpenHarmony.Native.Account"),
    "user_data.sms": ("sms", "OpenHarmony.Native.Sms"),
    "user_data.contacts": ("contacts", "OpenHarmony.Native.Contacts"),
    "user_data.calendar": ("calendar", "OpenHarmony.Native.Calendar"),
    "user_data.media": ("media_content", "OpenHarmony.Native.MediaContent"),
    "media.recording": ("media_recording", "OpenHarmony.Native.MediaRecording"),
    "user_preference.settings": ("settings", "OpenHarmony.Native.Settings"),
    "user_preference.locale": ("locale", "OpenHarmony.Native.Locale"),
    "user_preference.time": ("system_datetime", "OpenHarmony.Native.SystemDateTime"),
    "user_preference.input": ("input_method", "OpenHarmony.Native.InputMethod"),
    "network.cellular": ("cellular", "OpenHarmony.Native.Cellular"),
    "network.wifi": ("wifi_info", "OpenHarmony.Native.Wifi"),
    "network.bluetooth": ("bluetooth", "OpenHarmony.Native.Bluetooth"),
    "network.http": ("http", "OpenHarmony.Native.Http"),
    "network.socket": ("socket", "OpenHarmony.Native.Socket"),
    "network.webview": ("webview", "OpenHarmony.Native.WebView"),
    "network.upload": ("upload_download", "OpenHarmony.Native.UploadDownload"),
    "network.download": ("upload_download", "OpenHarmony.Native.UploadDownload"),
    "data_storage.preferences": ("preferences", "OpenHarmony.Native.Preferences"),
    "data_storage.database": ("database", "OpenHarmony.Native.Database"),
    "data_storage.distributed": ("distributed_storage", "OpenHarmony.Native.DistributedStorage"),
    "data_storage.filesystem": ("filesystem", "OpenHarmony.Native.FileSystem"),
    "user_data.file_picker": ("file_picker", "OpenHarmony.Native.FilePicker"),
    "user_data.cookie": ("webview_cookie", "OpenHarmony.Native.WebView"),
    "app_environment": ("app_environment", "OpenHarmony.Native.AppEnvironment"),
    "app_environment.permissions": ("permissions", "OpenHarmony.Native.Permissions"),
    "app_environment.installed_apps": ("installed_apps", "OpenHarmony.Native.InstalledApps"),
    "user_interaction.notification": ("notification", "OpenHarmony.Native.Notification"),
    "app_behavior.background": ("background_tasks", "OpenHarmony.Native.BackgroundTasks"),
    "app_analytics": ("analytics", "OpenHarmony.Native.Analytics"),
    "device_status.battery": ("battery", "OpenHarmony.Native.Battery"),
    "device_status.uptime": ("system_datetime", "OpenHarmony.Native.SystemDateTime"),
    "device_status.vibrator": ("vibrator", "OpenHarmony.Native.Vibrator"),
    "device_identity.screen": ("display", "OpenHarmony.Native.Display"),
    "device_identity.distributed": ("distributed_device", "OpenHarmony.Native.DistributedDevice"),
    "user_behavior.call": ("call", "OpenHarmony.Native.Call"),
}


# ==========================================================
# Symbol naming: namespace + method → OH_* symbol name
# ==========================================================

def make_symbol(namespace: str, method: str) -> str:
    """
    Convert ArkTS namespace.method to OH_* native symbol name.

    Format: OH_{Module}_{Operation} where Module includes namespace for clarity.
    Example: geoLocationManager.getCurrentLocation → OH_Location_GetCurrentLocation
    """
    MODULE_MAP = {
        "geoLocationManager": "Location",
        "audio": "Audio",
        "camera": "Camera",
        "wifiManager": "Wifi",
        "sim": "Sim",
        "radio": "Cellular",
        "access": "BluetoothAccess",
        "a2dp": "BluetoothA2dp",
        "connection": "BluetoothConnection",
        "contact": "Contact",
        "calendarManager": "Calendar",
        "osAccount": "OsAccount",
        "appAccount": "AppAccount",
        "distributedAccount": "DistributedAccount",
        "distributedDeviceManager": "DistributedDevice",
        "pasteboard": "Pasteboard",
        "sensor": "Sensor",
        "vibrator": "Vibrator",
        "batteryInfo": "Battery",
        "photoAccessHelper": "PhotoAccess",
        "media": "Media",
        "http": "Http",
        "socket": "Socket",
        "webview": "WebView",
        "settings": "Settings",
        "i18n": "Locale",
        "systemDateTime": "SystemDateTime",
        "inputMethod": "InputMethod",
        "preferences": "Preferences",
        "relationalStore": "Database",
        "distributedKVStore": "DistributedStorage",
        "fs": "FileSystem",
        "picker": "FilePicker",
        "bundleManager": "Bundle",
        "abilityAccessCtrl": "Permissions",
        "notificationManager": "Notification",
        "backgroundTaskManager": "BackgroundTask",
        "workScheduler": "WorkScheduler",
        "hiAppEvent": "Analytics",
        "display": "Display",
        "window": "Window",
        "mediaquery": "MediaQuery",
        "identifier": "Identifier",
        "call": "Call",
        "sms": "Sms",
    }

    METHOD_MAP = {
        "getCurrentLocation": "GetCurrentLocation",
        "getLastLocation": "GetLastLocation",
        "getCountryCode": "GetCountryCode",
        "isLocationEnabled": "IsLocatingEnabled",
        "getAddressesFromLocation": "GetAddressesFromLocation",
        "getAddressesFromLocationName": "GetAddressesFromLocationName",
        "isGeocoderAvailable": "IsGeocoderAvailable",
        "getCachedGnssLocationsSize": "GetCachedGnssLocationsSize",
        "on": "On",
        "off": "Off",
        "getSensorList": "GetInfos",
        "getSingleSensor": "GetSingleSensor",
        "once": "Once",
        "subscribe": "Subscribe",
        "unsubscribe": "Unsubscribe",
        "startVibration": "StartVibration",
        "getDeviceMacAddress": "GetDeviceMacAddress",
        "getLinkedInfo": "GetLinkedInfo",
        "getScanInfoList": "GetScanInfoList",
        "isConnected": "IsConnected",
        "getIpInfo": "GetIpInfo",
        "isWifiActive": "IsActive",
        "getState": "GetState",
        "getConnectionState": "GetConnectionState",
        "getPairedDevices": "GetPairedDevices",
        "getRemoteDeviceName": "GetRemoteDeviceName",
        "getRemoteDeviceClass": "GetRemoteDeviceClass",
        "getLocalName": "GetLocalName",
        "getSimOperatorNumeric": "GetOperatorNumeric",
        "getSimSpn": "GetSpn",
        "getSimAccountInfo": "GetAccountInfo",
        "getActiveSimAccountInfoList": "GetActiveAccountInfoList",
        "getISOCountryCodeForSimSync": "GetISOCountryCode",
        "getNetworkState": "GetNetworkState",
        "getSignalInformation": "GetSignalInformation",
        "getRadioTech": "GetRadioTech",
        "isNrSupported": "IsNrSupported",
        "getNetworkSelectionMode": "GetNetworkSelectionMode",
        "hasCall": "HasCall",
        "getCallState": "GetCallState",
        "getDefaultSmsSimId": "GetDefaultSimId",
        "getDefaultSmsSlotId": "GetDefaultSlotId",
        "hasSmsCapability": "HasCapability",
        "sendMessage": "SendMessage",
        "createMessage": "CreateMessage",
        "selectContacts": "SelectContacts",
        "queryContacts": "QueryContacts",
        "queryContact": "QueryContact",
        "queryContactsByPhoneNumber": "QueryByPhoneNumber",
        "queryContactsByEmail": "QueryByEmail",
        "queryGroups": "QueryGroups",
        "queryKey": "QueryKey",
        "getCalendarManager": "GetManager",
        "getCalendar": "GetCalendar",
        "getAllCalendars": "GetAllCalendars",
        "createCalendar": "CreateCalendar",
        "getEvents": "GetEvents",
        "addEvent": "AddEvent",
        "addEvents": "AddEvents",
        "getAccountManager": "GetManager",
        "getOsAccountLocalId": "GetLocalId",
        "queryOsAccountLocalIdFromProcess": "QueryLocalIdFromProcess",
        "createAppAccountManager": "CreateManager",
        "getAllAccounts": "GetAllAccounts",
        "createAccount": "CreateAccount",
        "getDistributedAccountAbility": "GetAbility",
        "getOsAccountDistributedInfo": "GetInfo",
        "createDeviceManager": "Create",
        "getLocalDeviceId": "GetLocalDeviceId",
        "getSystemPasteboard": "Create",
        "getData": "GetData",
        "getPasteData": "GetData",
        "hasData": "HasData",
        "batterySOC": "GetSOC",
        "chargingStatus": "GetChargingStatus",
        "healthStatus": "GetHealthStatus",
        "pluggedType": "GetPluggedType",
        "voltage": "GetVoltage",
        "technology": "GetTechnology",
        "batteryTemperature": "GetTemperature",
        "isBatteryPresent": "IsBatteryPresent",
        "batteryCapacityLevel": "GetCapacityLevel",
        "nowCurrent": "GetNowCurrent",
        "getPhotoAccessHelper": "Get",
        "getAssets": "GetAssets",
        "getAlbums": "GetAlbums",
        "createAsset": "CreateAsset",
        "createAVRecorder": "CreateAVRecorder",
        "createAVPlayer": "CreateAVPlayer",
        "createAudioRecorder": "Create",
        "createVideoRecorder": "Create",
        "createHttp": "Create",
        "request": "Request",
        "requestInStream": "RequestInStream",
        "constructTCPSocketInstance": "CreateTCP",
        "constructUDPSocketInstance": "CreateUDP",
        "constructTLSSocketInstance": "CreateTLS",
        "loadUrl": "LoadUrl",
        "runJavaScript": "RunJavaScript",
        "fetchCookie": "FetchCookie",
        "saveCookieAsync": "SaveCookieAsync",
        "configCookie": "ConfigCookie",
        "getValueSync": "GetValueSync",
        "getValue": "GetValue",
        "setValue": "SetValue",
        "getSystemLanguage": "GetSystemLanguage",
        "getSystemRegion": "GetSystemRegion",
        "getTimeZone": "GetTimeZone",
        "getSystemLocale": "GetSystemLocale",
        "is24HourClock": "Is24HourClock",
        "getPreferredLanguageList": "GetPreferredLanguageList",
        "getSystemCountries": "GetSystemCountries",
        "getDisplayCountry": "GetDisplayCountry",
        "getDisplayLanguage": "GetDisplayLanguage",
        "getCurrentTime": "GetCurrentTime",
        "getTimezone": "GetTimezone",
        "getUptime": "GetUptime",
        "getCurrentInputMethod": "GetCurrentMethod",
        "getSetting": "GetSetting",
        "getPreferences": "Get",
        "getPreferencesSync": "GetSync",
        "deletePreferences": "Delete",
        "getRdbStore": "Get",
        "deleteRdbStore": "Delete",
        "createKVManager": "CreateManager",
        "getKVStore": "Get",
        "open": "Open",
        "read": "Read",
        "write": "Write",
        "stat": "Stat",
        "listFile": "ListFile",
        "access": "Access",
        "getBundleInfoForSelf": "GetBundleInfoForSelf",
        "getAppInfo": "GetAppInfo",
        "getAllBundleInfo": "GetAllBundleInfo",
        "getBundleInfo": "GetBundleInfo",
        "checkAccessToken": "CheckAccessToken",
        "requestPermissionsFromUser": "RequestPermissions",
        "publish": "Publish",
        "requestEnableNotification": "RequestEnable",
        "requestSuspendDelay": "RequestSuspendDelay",
        "startBackgroundRunning": "StartBackgroundRunning",
        "startWork": "StartWork",
        "getDefaultDisplaySync": "GetDefaultDisplaySync",
        "getAllDisplays": "GetAllDisplays",
        "getLastWindow": "GetLastWindow",
        "getWindowProperties": "GetProperties",
        "matchMediaSync": "MatchMediaSync",
        "getOAID": "GetOAID",
    }

    module = MODULE_MAP.get(namespace, namespace)
    operation = METHOD_MAP.get(method, method)

    if operation and operation[0].islower():
        operation = operation[0].upper() + operation[1:]

    return f"OH_{module}_{operation}"


def make_entry(namespace: str, method: str, profiling_category: str, data_direction: str) -> dict:
    """Generate a native API rule entry."""
    if profiling_category not in CATEGORY_MAP:
        return None

    category, api_package = CATEGORY_MAP[profiling_category]
    symbol = make_symbol(namespace, method)

    return {
        "symbol": symbol,
        "prototype": f"unknown {symbol}(...)",
        "category": category,
        "profilingCategory": profiling_category,
        "apiPackage": api_package,
        "dataDirection": data_direction,
        "matchModes": ["import_symbol", "string_reference"]
    }


def main():
    script_dir = Path(__file__).parent
    native_json = script_dir.parent / "native_privacy_apis.json"
    arkts_json = script_dir.parent / "privacy_apis.json"

    # Load existing native rules
    with open(native_json, "r", encoding="utf-8") as f:
        native_data = json.load(f)

    # Load ArkTS rules
    with open(arkts_json, "r", encoding="utf-8") as f:
        arkts_data = json.load(f)

    # Build existing symbol set
    existing_symbols = {entry["symbol"] for entry in native_data["nativeApis"]}

    # Collect all ArkTS rules grouped by dataDirection
    arkts_rules = []
    for pkg in arkts_data:
        for rule in pkg.get("privacyApis", []):
            arkts_rules.append({
                "namespace": rule["namespace"],
                "method": rule["method"],
                "profilingCategory": rule["profilingCategory"],
                "dataDirection": rule["dataDirection"],
            })

    # Generate missing native entries
    added = 0
    skipped_dup = 0
    skipped_excluded = 0

    for rule in arkts_rules:
        pc = rule["profilingCategory"]
        dd = rule["dataDirection"]

        # Skip excluded rules
        if dd == "excluded":
            skipped_excluded += 1
            continue

        symbol = make_symbol(rule["namespace"], rule["method"])

        # Skip if already exists
        if symbol in existing_symbols:
            skipped_dup += 1
            continue

        entry = make_entry(rule["namespace"], rule["method"], pc, dd)
        if entry:
            native_data["nativeApis"].append(entry)
            added += 1
            print(f"  + {symbol} ({pc})")

    print(f"\n[*] Summary:")
    print(f"    Already existing: {skipped_dup}")
    print(f"    Skipped (excluded): {skipped_excluded}")
    print(f"    Newly added: {added}")

    # Backup original
    backup_path = native_json.with_suffix(".json.bak")
    if not backup_path.exists():
        import shutil
        shutil.copy2(native_json, backup_path)
        print(f"[*] Backup created: {backup_path}")

    # Write updated file
    with open(native_json, "w", encoding="utf-8") as f:
        json.dump(native_data, f, ensure_ascii=False, indent=2)

    print(f"[+] Written to {native_json}")


if __name__ == "__main__":
    main()