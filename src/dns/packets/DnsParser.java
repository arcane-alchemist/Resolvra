package dns.packets;

import java.util.ArrayList;
import java.util.List;

public class DnsParser {

    public static DnsPacket parse(byte[] data, int length) {

        if (length < 12) {
            throw new IllegalArgumentException(
                    "DNS packet must contain at least 12 bytes"
            );
        }

        DnsHeader header = parseHeader(data);

        int offset = 12;

        List<DnsQuestion> questions = new ArrayList<>();

        for (int i = 0; i < header.getQuestionCount(); i++) {

            NameResult nameResult = readName(data, offset);

            offset = nameResult.nextOffset;

            int type = readUnsignedShort(data, offset);
            offset += 2;

            int dnsClass = readUnsignedShort(data, offset);
            offset += 2;

            questions.add(
                    new DnsQuestion(
                            nameResult.name,
                            type,
                            dnsClass
                    )
            );
        }

        return new DnsPacket(
                header,
                questions,
                new ArrayList<>()
        );
    }

    public static DnsHeader parseHeader(byte[] data) {

        if (data.length < 12) {
            throw new IllegalArgumentException(
                    "DNS packet must contain at least 12 bytes"
            );
        }

        int id = readUnsignedShort(data, 0);
        int flags = readUnsignedShort(data, 2);
        int questionCount = readUnsignedShort(data, 4);
        int answerCount = readUnsignedShort(data, 6);
        int authorityCount = readUnsignedShort(data, 8);
        int additionalCount = readUnsignedShort(data, 10);

        return new DnsHeader(
                id,
                flags,
                questionCount,
                answerCount,
                authorityCount,
                additionalCount
        );
    }

    private static int readUnsignedShort(byte[] data, int offset) {

        return ((data[offset] & 0xFF) << 8)
                | (data[offset + 1] & 0xFF);
    }

    private static NameResult readName(byte[] data, int offset) {

        StringBuilder name = new StringBuilder();

        while (true) {

            int length = data[offset] & 0xFF;
            offset++;

            if (length == 0) {
                break;
            }

            if (name.length() > 0) {
                name.append(".");
            }

            for (int i = 0; i < length; i++) {
                name.append((char) (data[offset] & 0xFF));
                offset++;
            }
        }

        return new NameResult(
                name.toString(),
                offset
        );
    }

    private static class NameResult {

        String name;
        int nextOffset;

        NameResult(String name, int nextOffset) {
            this.name = name;
            this.nextOffset = nextOffset;
        }
    }
}
