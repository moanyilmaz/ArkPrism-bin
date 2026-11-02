/**
 * Fix dataDirection in privacy_apis.json based on semantic rules.
 *
 * Core principle:
 *   - source: API returns/reads sensitive data (data flows FROM the system)
 *   - sink: API sends/writes/persists data (data flows TO the system/network)
 *   - both: API can both read and write (e.g., clipboard, event subscription)
 *
 * Inference priority:
 *   1. Explicit overrides for known tricky cases
 *   2. Method-name heuristics combined with category context
 *   3. Category-based defaults
 */

const fs = require('fs');
const path = require('path');

const INPUT = path.join(__dirname, '..', 'config', 'privacy_apis.json');
const OUTPUT = path.join(__dirname, '..', 'config', 'privacy_apis.json');

// Source method prefixes: methods that READ/RETURN data
const SOURCE_PREFIXES = [
    'get', 'query', 'is', 'check', 'select', 'fetch',
    'list', 'find', 'search', 'read', 'obtain',
    'acquire', 'retrieve', 'has', 'can'
];

// Sink method prefixes: methods that WRITE/SEND/PERSIST data
const SINK_PREFIXES = [
    'add', 'set', 'write', 'send', 'post', 'upload',
    'insert', 'save', 'delete', 'remove', 'enable',
    'disable', 'start', 'stop', 'close', 'publish',
    'share', 'update', 'put', 'grant', 'connect',
    'disconnect', 'pair', 'download', 'limit'
];

// Both method prefixes: methods that subscribe to data streams
const BOTH_PREFIXES = [
    'on', 'off'  // event listener registration = subscribe to data
];

// Known profilingCategory corrections (source data errors)
const CATEGORY_FIXES = {
    'userAuth:getAvailableStatus': 'device_identity.biometric',
    'UserAuth:getAvailableStatus': 'device_identity.biometric',
};

// Explicit dataDirection overrides for tricky cases
const DIRECTION_OVERRIDES = {
    // create* in user_data.account: creates a request to obtain data → source
    'HuaweiIDProvider:createLoginWithHuaweiIDRequest': 'source',
    'HuaweiIDProvider:createAuthorizationWithHuaweiIDRequest': 'source',
    'AuthenticationController:executeRequest': 'source',
    // create* in biometric: creates auth session → source (returns instance)
    'userAuth:getUserAuthInstance': 'source',
    'UserAuth:getAvailableStatus': 'source',
    'userAuth:getAvailableStatus': 'source',
    // Clipboard read operations → both (read sensitive data, context determines direction)
    'pasteboard:getSystemPasteboard': 'both',
    'SystemPasteboard:getData': 'both',
    'PasteData:getPrimaryText': 'both',
    // Clipboard write operations → sink
    'SystemPasteboard:setData': 'sink',
    'SystemPasteboard:setAppShareOptions': 'sink',
    'SystemPasteboard:removeAppShareOptions': 'sink',
    // Camera input creation → source (captures image)
    'camera:createCameraInput': 'source',
    // Audio capturer → source (records audio)
    'audio:createAudioCapturer': 'source',
    'audio:createAudioLoopback': 'source',
    // Photo asset creation → sink (writes to gallery)
    'photoAccessHelper:createAsset': 'sink',
    'PhotoAccessHelper:createAsset': 'sink',
    'photoAccessHelper:delete': 'sink',
    'PhotoAccessHelper:delete': 'sink',
};

function hasPrefix(method, prefixes) {
    const lower = method.toLowerCase();
    return prefixes.some(p => lower.startsWith(p.toLowerCase()));
}

function inferDataDirection(method, category, key) {
    // 1. Check explicit overrides first
    if (DIRECTION_OVERRIDES[key]) {
        return DIRECTION_OVERRIDES[key];
    }

    const isSourcePrefix = hasPrefix(method, SOURCE_PREFIXES);
    const isSinkPrefix = hasPrefix(method, SINK_PREFIXES);
    const isBothPrefix = hasPrefix(method, BOTH_PREFIXES);

    const isUserCategory = category.startsWith('user_data.');
    const isNetworkCategory = category.startsWith('network.');
    const isLocationCategory = category === 'location';
    const isDeviceIdentityCategory = category.startsWith('device_identity.');
    const isDeviceStatusCategory = category.startsWith('device_status.');

    // 2. Method-name heuristics with category context

    // Event listener registration: on/off → "both" (subscribe to data stream)
    // But NOT for sensor.once which is just a one-time read
    if (isBothPrefix && !method.toLowerCase().startsWith('once')) {
        return 'both';
    }

    // For network.bluetooth:
    //   - Read methods (get*, is*, check*) → source (return device/connection info)
    //   - Write/control methods (set*, add*, enable*, disable*, start*, stop*) → sink
    if (category === 'network.bluetooth') {
        if (isSourcePrefix) return 'source';
        if (isSinkPrefix) return 'sink';
        return 'source'; // default for bluetooth
    }

    // For network.connectivity:
    //   - Read methods → source (get network info)
    //   - Write/connect methods → sink (send data, establish connections)
    if (category === 'network.connectivity') {
        if (isSourcePrefix) return 'source';
        if (isSinkPrefix) return 'sink';
        return 'sink'; // default for connectivity
    }

    // For network.wifi:
    //   - Read methods → source (get WiFi info)
    //   - Write/control methods → sink (configure WiFi)
    if (category === 'network.wifi') {
        if (isSourcePrefix) return 'source';
        if (isSinkPrefix) return 'sink';
        return 'source'; // default for wifi
    }

    // For user_data.*:
    //   - Read methods → source (return personal data)
    //   - Write methods → sink (persist personal data)
    if (isUserCategory) {
        if (isSourcePrefix && isSinkPrefix) return 'both';
        if (isSinkPrefix) return 'sink';
        if (isSourcePrefix) return 'source';
        return 'source'; // default for user_data
    }

    // For location:
    //   - Read methods → source
    //   - Write/control methods → sink (set geofences, etc.)
    if (isLocationCategory) {
        if (isSourcePrefix) return 'source';
        if (isSinkPrefix) return 'sink';
        return 'source';
    }

    // For device_identity.*: mostly source (return device identifiers)
    if (isDeviceIdentityCategory) {
        if (isSinkPrefix) return 'sink'; // e.g., setDeviceName
        return 'source';
    }

    // For device_status.*: mostly source (return device state)
    if (isDeviceStatusCategory) {
        if (isSinkPrefix) return 'sink';
        return 'source';
    }

    // 3. Fallback: method-name only
    if (isSourcePrefix && isSinkPrefix) return 'both';
    if (isSourcePrefix) return 'source';
    if (isSinkPrefix) return 'sink';

    // 4. Category-based default
    if (isNetworkCategory) return 'sink';
    return 'source';
}

function main() {
    const data = JSON.parse(fs.readFileSync(INPUT, 'utf-8'));

    let totalApis = 0;
    let fixedDirection = 0;
    let fixedCategory = 0;
    const directionChanges = {};

    data.forEach(group => {
        if (!group.privacyApis) return;

        group.privacyApis.forEach(api => {
            totalApis++;
            const key = `${api.namespace}:${api.method}`;

            // Fix profilingCategory
            if (CATEGORY_FIXES[key]) {
                const oldCat = api.profilingCategory;
                api.profilingCategory = CATEGORY_FIXES[key];
                if (oldCat !== CATEGORY_FIXES[key]) {
                    fixedCategory++;
                    console.log(`  [CATEGORY FIX] ${key}: ${oldCat} → ${CATEGORY_FIXES[key]}`);
                }
            }

            // Infer correct dataDirection
            const oldDir = api.dataDirection;
            const newDir = inferDataDirection(api.method, api.profilingCategory, key);

            if (oldDir !== newDir) {
                fixedDirection++;
                const changeKey = `${oldDir}→${newDir}`;
                directionChanges[changeKey] = (directionChanges[changeKey] || 0) + 1;
                console.log(`  [DIRECTION FIX] ${api.namespace}.${api.method}: ${oldDir} → ${newDir} (category: ${api.profilingCategory})`);
            }

            api.dataDirection = newDir;
        });
    });

    // Write back
    fs.writeFileSync(OUTPUT, JSON.stringify(data, null, 4), 'utf-8');

    console.log('\n--- Summary ---');
    console.log(`Total APIs: ${totalApis}`);
    console.log(`Category fixes: ${fixedCategory}`);
    console.log(`Direction fixes: ${fixedDirection}`);
    console.log('Direction changes breakdown:');
    Object.entries(directionChanges)
        .sort((a, b) => b[1] - a[1])
        .forEach(([k, v]) => console.log(`  ${k}: ${v}`));
}

main();
