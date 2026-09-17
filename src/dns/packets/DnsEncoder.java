package dns.packets;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.util.List;

public class DnsEncoder {

    public static byte[] buildResponse(
            DnsPacket request,
            List<DnsRecord> answers) throws IOException {

        ByteArrayOutputStream out =
                new ByteArrayOutputStream();

        DnsHeader requestHeader = request.getHeader();

        int flags = 0x8000 | 0x0400;

        writeShort(out, requestHeader.getId());
        writeShort(out, flags);
        writeShort(out, request.getQuestions().size());
        writeShort(out, answers.size());
        writeShort(out, 0);
        writeShort(out, 0);

        for (DnsQuestion question : request.getQuestions()) {

            writeName(out, question.getName());

            writeShort(out, question.getType());
            writeShort(out, question.getDnsClass());
        }

        for (DnsRecord record : answers) {

            if (record instanceof dns.records.ARecord aRecord) {

                writeName(out, record.getName());

                writeShort(out, 1);
                writeShort(out, 1);
                writeInt(out, record.getTtl());

                byte[] address =
                        InetAddress.getByName(
                                aRecord.getAddress()
                        ).getAddress();

                writeShort(out, address.length);
                out.write(address);
            }
        }

        return out.toByteArray();
    }

    private static void writeName(
            ByteArrayOutputStream out,
            String name) {

        String[] labels = name.split("\\.");

        for (String label : labels) {

            out.write(label.length());

            byte[] bytes =
                    label.getBytes();

            out.writeBytes(bytes);
        }

        out.write(0);
    }

    private static void writeShort(
            ByteArrayOutputStream out,
            int value) {

        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }

    private static void writeInt(
            ByteArrayOutputStream out,
            int value) {

        out.write((value >> 24) & 0xFF);
        out.write((value >> 16) & 0xFF);
        out.write((value >> 8) & 0xFF);
        out.write(value & 0xFF);
    }
}
