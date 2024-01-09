package org.openhab.binding.mideaac.internal.handler;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import org.apache.commons.lang3.ArrayUtils;

/**
 * Discovery service for Midea AC.
 *
 * @author Jacek Dobrowolski
 */
public class Packet {
    private final CommandBase command;
    private byte[] packet;
    private final MideaACHandler mideaACHandler;
    // private static Logger logger = LoggerFactory.getLogger(Packet.class);

    public Packet(CommandBase command, String deviceId, MideaACHandler mideaACHandler) {
        this.command = command;
        this.mideaACHandler = mideaACHandler;

        packet = new byte[] {
                // 2 bytes - StaticHeader
                (byte) 0x5a, (byte) 0x5a,
                // 2 bytes - mMessageType
                (byte) 0x01, (byte) 0x11,
                // 2 bytes - PacketLenght
                (byte) 0x00, (byte) 0x00,
                // 2 bytes
                (byte) 0x20, (byte) 0x00,
                // 4 bytes - MessageId
                0x00, 0x00, 0x00, 0x00,
                // 8 bytes - Date&Time
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                // 6 bytes - mDeviceID
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                // 14 bytes
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        Calendar cal = Calendar.getInstance();
        cal.setTime(new Date());

        // Date d = new Date();
        // d.g
        // int i = cal.get(Calendar.SECOND);
        // byte[] datetimeBytes = { (byte) (d.getYear() / 100), (byte) (d.getYear() % 100), (byte) d.getMonth(), (byte)
        // d.getDate(), (byte) d.getHours(), (byte) d.getMinutes(), (byte) d.getSeconds(), 0x00 }; // TOOD:
        byte[] datetimeBytes = { (byte) (cal.get(Calendar.YEAR) / 100), (byte) (cal.get(Calendar.YEAR) % 100),
                (byte) cal.get(Calendar.MONTH), (byte) cal.get(Calendar.DATE), (byte) cal.get(Calendar.HOUR),
                (byte) cal.get(Calendar.MINUTE), (byte) cal.get(Calendar.SECOND), 0x00 }; // TOOD:
        // set
        // milliseconds
        System.arraycopy(datetimeBytes, 0, packet, 12, 8);

        byte[] idBytes = new BigInteger(deviceId).toByteArray();
        ArrayUtils.reverse(idBytes);
        System.arraycopy(idBytes, 0, packet, 20, 6);
    }

    @Override
    public void finalize() {
        command.finalize();

        // Append the command data(48 bytes) to the packet
        byte[] cmdEncrypted = mideaACHandler.getSecurity().aes_encrypt(command.getBytes());
        packet = ArrayUtils.addAll(packet, Arrays.copyOf(cmdEncrypted, 48));

        // PacketLenght
        byte[] lenBytes = { (byte) (packet.length + 16), 0 };

        System.arraycopy(lenBytes, 0, packet, 4, 2);

        // Append a basic checksum data(16 bytes) to the packet
        packet = ArrayUtils.addAll(packet, mideaACHandler.getSecurity().encode32_data(packet));
    }

    public byte[] getBytes() {
        return packet;
    }
}
