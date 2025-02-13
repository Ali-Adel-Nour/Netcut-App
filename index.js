import { startCLI, monitorDevice, showDeviceList } from './src/cli/interface.js';
import logger from './src/utils/logger.js';

async function main() {
    try {
        logger.info('Starting Net-Cut application...');
        const target = await startCLI();

        if (!target) {
            logger.error('No target selected');
            process.exit(1);
        }

        logger.info(`Selected target: ${target.ip}`);

        await monitorDevice(target);
    } catch (error) {
        logger.error('Application error:', error);
        process.exit(1);
    }
}

main().catch(error => {
    logger.error('Fatal error:', error);
    process.exit(1);
});
