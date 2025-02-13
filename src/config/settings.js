import dotenv from 'dotenv';
dotenv.config();

const config = {
    network: {
        interface: process.env.NETWORK_INTERFACE,
        gatewayIP: process.env.GATEWAY_IP,
        subnetMask: process.env.SUBNET_MASK
    },
    attack: {
        packetInterval: parseInt(process.env.PACKET_INTERVAL),
        spoofInterval: parseInt(process.env.SPOOF_INTERVAL),
        restoreDelay: parseInt(process.env.RESTORE_DELAY),
        maxRetries: parseInt(process.env.MAX_RETRIES)
    },
    monitoring: {
        scanTimeout: parseInt(process.env.SCAN_TIMEOUT),
        monitorInterval: parseInt(process.env.MONITOR_INTERVAL)
    },
    security: {
        requireSudo: process.env.REQUIRE_SUDO === 'true',
        maxTargets: parseInt(process.env.MAX_CONCURRENT_TARGETS),
        blockBlacklist: process.env.BLOCK_BLACKLIST === 'true'
    },
    app: {
        logLevel: process.env.LOG_LEVEL,
        debug: process.env.DEBUG === 'true'
    }
};


export default config;