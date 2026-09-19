package dns.packets;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class DnsPacketWriter {

    private final ByteArrayOutputStream out =
            new ByteArrayOutputStream();

    private final Map<String, Integer> compression =
            new HashMap<>();

    public int position() {
        return out.size();
    }

    public void writeByte(int value) {
        out.write(value & 0xFF);
    }

    public void writeShort(int value) {
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    public void writeInt(int value) {
        out.write((value >> 24) & 0xFF);
        out.write((value >> 16) & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    public void writeBytes(byte[] data) {
        out.writeBytes(data);
    }

    public void writeName(String name) {

        String cleanName =
                normalizeName(name);

        if (cleanName.isEmpty()) {
            writeByte(0);
            return;
        }

        String[] labels =
                cleanName.split("\\.");

        for (int i = 0; i < labels.length; i++) {

            String suffix =
                    buildSuffix(labels, i);

            Integer pointer =
                    compression.get(suffix);

            if (pointer != null) {
                writePointer(pointer);
                return;
            }

            compression.put(
                    suffix,
                    position()
            );

            byte[] label =
                    labels[i].getBytes(
                            StandardCharsets.US_ASCII
                    );

            if (label.length > 63) {
                throw new IllegalArgumentException(
                        "DNS label is longer than 63 bytes"
                );
            }

            writeByte(label.length);
            writeBytes(label);
        }

        writeByte(0);
    }

    public void writePointer(int offset) {

        if (offset < 0 || offset > 0x3FFF) {
            throw new IllegalArgumentException(
                    "Invalid DNS compression offset: "
                    + offset
            );
        }

        int pointer =
                0xC000 | offset;

        writeShort(pointer);
    }

    /*
     * Reserve two bytes for a value that will
     * be filled in later.
     */
    public int reserveShort() {

        int position = position();

        writeShort(0);

        return position;
    }

    /*
     * Replace a previously written 16-bit value.
     */
    public void setShort(
            int offset,
            int value) {

        byte[] data =
                out.toByteArray();

        if (offset < 0
                || offset + 1 >= data.length) {

            throw new IllegalArgumentException(
                    "Invalid packet offset: "
                    + offset
            );
        }

        data[offset] =
                (byte) ((value >> 8) & 0xFF);

        data[offset + 1] =
                (byte) (value & 0xFF);

        out.reset();

        out.writeBytes(data);
    }

    public byte[] toByteArray() {
        return out.toByteArray();
    }

    private static String buildSuffix(
            String[] labels,
            int start) {

        StringBuilder result =
                new StringBuilder();

        for (int i = start;
             i < labels.length;
             i++) {

            if (result.length() > 0) {
                result.append(".");
            }

            result.append(
                    labels[i].toLowerCase()
            );
        }

        return result.toString();
    }

    private static String normalizeName(
            String name) {

        if (name == null) {
            return "";
        }

        String result =
                name.trim()
                        .toLowerCase();

        while (
                result.endsWith(".")
                && result.length() > 0
        ) {
            result =
                    result.substring(
                            0,
                            result.length() - 1
                    );
        }

        return result;
    }
}
