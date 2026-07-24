package com.packetanalyzer;

public class PacketParser {

    public static Packet parseEthernetFrame(double timestamp, byte[] data) {
        if (data.length < 14) return null;

        int ethType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);
        int ipHeaderOffset = 14;

        if (ethType == 0x8100) {
            ipHeaderOffset += 4;
            ethType = ((data[16] & 0xFF) << 8) | (data[17] & 0xFF);
        }

        if (ethType != 0x0800) {
            return new Packet(timestamp, "UNKNOWN", "UNKNOWN", 0, 0, "NON-IPv4", data);
        }

        if (data.length < ipHeaderOffset + 20) return null;

        int ihl = (data[ipHeaderOffset] & 0x0F) * 4;
        int protocolType = data[ipHeaderOffset + 9] & 0xFF;

        String srcIp = String.format("%d.%d.%d.%d",
                data[ipHeaderOffset + 12] & 0xFF, data[ipHeaderOffset + 13] & 0xFF,
                data[ipHeaderOffset + 14] & 0xFF, data[ipHeaderOffset + 15] & 0xFF);

        String dstIp = String.format("%d.%d.%d.%d",
                data[ipHeaderOffset + 16] & 0xFF, data[ipHeaderOffset + 17] & 0xFF,
                data[ipHeaderOffset + 18] & 0xFF, data[ipHeaderOffset + 19] & 0xFF);

        int transportOffset = ipHeaderOffset + ihl;
        if (data.length < transportOffset + 4) {
            return new Packet(timestamp, srcIp, dstIp, 0, 0, "IP", new byte[0]);
        }

        int srcPort = ((data[transportOffset] & 0xFF) << 8) | (data[transportOffset + 1] & 0xFF);
        int dstPort = ((data[transportOffset + 2] & 0xFF) << 8) | (data[transportOffset + 3] & 0xFF);

        String protocolStr = "OTHER";
        int payloadOffset = transportOffset;

        if (protocolType == 6) {
            protocolStr = "TCP";
            int dataOffset = ((data[transportOffset + 12] >> 4) & 0x0F) * 4;
            payloadOffset += dataOffset;
        } else if (protocolType == 17) {
            protocolStr = "UDP";
            payloadOffset += 8;
        }

        byte[] payload = new byte[0];
        if (payloadOffset < data.length) {
            int payloadLen = data.length - payloadOffset;
            payload = new byte[payloadLen];
            System.arraycopy(data, payloadOffset, payload, 0, payloadLen);
        }

        return new Packet(timestamp, srcIp, dstIp, srcPort, dstPort, protocolStr, payload);
    }
}
