package dns.packets;

import java.util.ArrayList;
import java.util.List;

public class DnsParser {

    public static DnsPacket parse(
            byte[] data,
            int length) {

        if (length < 12) {
            throw new IllegalArgumentException(
                    "DNS packet must contain at least 12 bytes"
            );
        }

        DnsHeader header =
                parseHeader(data, length);

        int offset = 12;

        List<DnsQuestion> questions =
                new ArrayList<>();

        for (int i = 0;
             i < header.getQuestionCount();
             i++) {

            NameResult nameResult =
                    readName(
                            data,
                            length,
                            offset
                    );

            offset = nameResult.nextOffset;

            int type =
                    readUnsignedShort(
                            data,
                            offset,
                            length
                    );

            offset += 2;

            int dnsClass =
                    readUnsignedShort(
                            data,
                            offset,
                            length
                    );

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

    public static DnsHeader parseHeader(
            byte[] data,
            int length) {

        if (length < 12) {
            throw new IllegalArgumentException(
                    "DNS packet must contain at least 12 bytes"
            );
        }

        int id =
                readUnsignedShort(
                        data,
                        0,
                        length
                );

        int flags =
                readUnsignedShort(
                        data,
                        2,
                        length
                );

        int questionCount =
                readUnsignedShort(
                        data,
                        4,
                        length
                );

        int answerCount =
                readUnsignedShort(
                        data,
                        6,
                        length
                );

        int authorityCount =
                readUnsignedShort(
                        data,
                        8,
                        length
                );

        int additionalCount =
                readUnsignedShort(
                        data,
                        10,
                        length
                );

        return new DnsHeader(
                id,
                flags,
                questionCount,
                answerCount,
                authorityCount,
                additionalCount
        );
    }

    private static int readUnsignedShort(
            byte[] data,
            int offset,
            int length) {

        if (offset < 0
                || offset + 2 > length) {

            throw new IllegalArgumentException(
                    "Unexpected end of DNS packet"
            );
        }

        return ((data[offset] & 0xFF) << 8)
                | (data[offset + 1] & 0xFF);
    }

    private static NameResult readName(
            byte[] data,
            int length,
            int offset) {

        StringBuilder name =
                new StringBuilder();

        int currentOffset = offset;

        /*
         * This tells us where the next DNS
         * field begins in the original packet.
         *
         * A compression pointer changes where
         * we read the name from, but it does NOT
         * change where the following field starts.
         */
        int nextOffset = -1;

        /*
         * Prevent malformed packets from creating
         * an infinite compression-pointer loop.
         */
        boolean[] visited =
                new boolean[length];

        while (true) {

            if (currentOffset < 0
                    || currentOffset >= length) {

                throw new IllegalArgumentException(
                        "Invalid DNS name offset"
                );
            }

            if (visited[currentOffset]) {

                throw new IllegalArgumentException(
                        "DNS compression pointer loop"
                );
            }

            visited[currentOffset] = true;

            int firstByte =
                    data[currentOffset] & 0xFF;

            /*
             * 11xxxxxx means this is a DNS
             * compression pointer.
             */
            if ((firstByte & 0xC0) == 0xC0) {

                if (currentOffset + 1 >= length) {

                    throw new IllegalArgumentException(
                            "Incomplete DNS compression pointer"
                    );
                }

                int secondByte =
                        data[currentOffset + 1]
                                & 0xFF;

                int pointer =
                        ((firstByte & 0x3F) << 8)
                        | secondByte;

                if (pointer >= length) {

                    throw new IllegalArgumentException(
                            "DNS compression pointer "
                            + "outside packet"
                    );
                }

                /*
                 * The two pointer bytes belong to
                 * the current field, so if this is
                 * the first pointer encountered,
                 * the next DNS field starts after
                 * these two bytes.
                 */
                if (nextOffset == -1) {

                    nextOffset =
                            currentOffset + 2;
                }

                currentOffset = pointer;

                continue;
            }

            /*
             * 01xxxxxx, 10xxxxxx and 11xxxxxx
             * have special meanings in DNS.
             *
             * We only allow normal labels (00xxxxxx)
             * or compression pointers (11xxxxxx).
             */
            if ((firstByte & 0xC0) != 0) {

                throw new IllegalArgumentException(
                        "Invalid DNS label format"
                );
            }

            int labelLength =
                    firstByte;

            currentOffset++;

            /*
             * Zero-length label means the end
             * of the domain name.
             */
            if (labelLength == 0) {

                if (nextOffset == -1) {
                    nextOffset =
                            currentOffset;
                }

                break;
            }

            if (labelLength > 63) {

                throw new IllegalArgumentException(
                        "DNS label is longer than 63 bytes"
                );
            }

            if (currentOffset + labelLength
                    > length) {

                throw new IllegalArgumentException(
                        "DNS label extends beyond packet"
                );
            }

            if (name.length() > 0) {
                name.append(".");
            }

            for (int i = 0;
                 i < labelLength;
                 i++) {

                name.append(
                        (char)
                                (data[
                                        currentOffset + i
                                ] & 0xFF)
                );
            }

            currentOffset += labelLength;
        }

        return new NameResult(
                name.toString(),
                nextOffset
        );
    }

    private static class NameResult {

        final String name;
        final int nextOffset;

        NameResult(
                String name,
                int nextOffset) {

            this.name = name;
            this.nextOffset = nextOffset;
        }
    }
}
