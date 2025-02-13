import inquirer from 'inquirer';
import NetworkUtils from '../utils/network.js';
import logger from '../utils/logger.js';

async function startCLI() {
    try {
        return await showDeviceList();
    } catch (error) {
        logger.error('CLI Error:', error);
        return null;
    }
}

async function monitorDevice(target) {
    console.clear();
    console.log(`\nMonitoring ${target.ip} (${target.mac})`);
    console.log('Press: SPACE to attack, B to set bandwidth, Ctrl+C to exit\n');

    let attack = null;
    let isRunning = true;

    // Status monitoring
    const statusInterval = setInterval(async () => {
        if (!isRunning) return;
        const isOnline = await NetworkUtils.checkDeviceStatus(target.ip);
        process.stdout.write(`\rStatus: ${isOnline ? 'Online' : 'Offline'}     `);
    }, 2000);

    return new Promise((resolve) => {
        process.stdin.setRawMode(true);
        process.stdin.resume();
        process.stdin.on('data', async (key) => {
            try {
                if (key[0] === 32) { // Space
                    const { gateway } = await NetworkUtils.getGatewayInfo();
                    const ourMAC = await NetworkUtils.getMACAddress(gateway);

                    if (!attack) {
                        attack = await NetworkUtils.attackDevice(target.ip, gateway, ourMAC);
                        console.log('\nAttack started - Press B to set bandwidth');
                    } else {
                        await attack.stop();
                        attack = null;
                        console.log('\nAttack stopped');
                    }
                } else if (key[0] === 98 && attack) { // 'b'
                    const { limit } = await inquirer.prompt([{
                        type: 'input',
                        name: 'limit',
                        message: 'Enter bandwidth limit (Kbps):',
                        default: '100'
                    }]);
                    await attack.setBandwidth(parseInt(limit));
                    console.log(`\nBandwidth limited to ${limit}Kbps`);
                } else if (key[0] === 3) { // Ctrl+C
                    isRunning = false;
                    clearInterval(statusInterval);
                    if (attack) await attack.stop();
                    process.stdin.setRawMode(false);
                    resolve();
                }
            } catch (error) {
                console.error('Error handling input:', error);
            }
        });
    });
}

async function showDeviceList() {
    const devices = await NetworkUtils.scanNetwork();
    if (!devices || devices.length === 0) {
        logger.warn('No devices found');
        return null;
    }

    const choices = devices.map(d => ({
        name: `${d.ip} (${d.mac})`,
        value: d
    }));

    const answer = await inquirer.prompt([{
        type: 'list',
        name: 'target',
        message: 'Select target to monitor:',
        choices,
        pageSize: 10
    }]);

    return answer.target || null;
}

export { startCLI,monitorDevice,showDeviceList }  ;
