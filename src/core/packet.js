function createARPPacket(srcMAC, srcIP, dstMAC, dstIP, operation) {
    const packet = Buffer.alloc(42);

    // Ethernet header
    dstMAC.split(':').forEach((octet, i) => packet[i] = parseInt(octet, 16));
    srcMAC.split(':').forEach((octet, i) => packet[6 + i] = parseInt(octet, 16));
    packet.writeUInt16BE(0x0806, 12);

    // ARP header
    packet.writeUInt16BE(0x0001, 14);
    packet.writeUInt16BE(0x0800, 16);
    packet[18] = 6;
    packet[19] = 4;
    packet.writeUInt16BE(operation, 20);

    return packet;
}

module.exports = { createARPPacket };