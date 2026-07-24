package com.packetanalyzer;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapReader implements AutoCloseable {
    private final DataInputStream is;
    private boolean littleEndian = false;

    public PcapReader(String filePath) throws IOException {
        this.is = new DataInputStream(new FileInputStream(filePath));
        readGlobalHeader();
    }

    private void readGlobalHeader() throws IOException {
        byte[] magic = new byte[4];
        is.readFully(magic);
        int magicInt = ((magic[0] & 0xFF) << 24) | ((magic[1] & 0xFF) << 16) |
                       ((magic[2] & 0xFF) << 8) | (magic[3] & 0xFF);

        if (magicInt == 0xa1b2c3d4) {
            littleEndian = false;
        } else if (magicInt == 0xd4c3b2a1) {
            littleEndian = true;
        } else {
            throw new IOException("Not a valid PCAP file format (magic: " + Integer.toHexString(magicInt) + ")");
        }

        byte[] restHeader = new byte[20];
        is.readFully(restHeader);
    }

    public Packet readNextPacket() throws IOException {
        byte[] pktHeader = new byte[16];
        try {
            is.readFully(pktHeader);
        } catch (IOException e) {
            return null;
        }

        ByteBuffer bb = ByteBuffer.wrap(pktHeader);
        bb.order(littleEndian ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN);

        long tsSec = bb.getInt() & 0xFFFFFFFFL;
        long tsUsec = bb.getInt() & 0xFFFFFFFFL;
        int inclLen = bb.getInt();
        int origLen = bb.getInt();

        byte[] packetData = new byte[inclLen];
        is.readFully(packetData);

        return PacketParser.parseEthernetFrame(tsSec + (tsUsec / 1000000.0), packetData);
    }

    @Override
    public void close() throws IOException {
        if (is != null) is.close();
    }
}
