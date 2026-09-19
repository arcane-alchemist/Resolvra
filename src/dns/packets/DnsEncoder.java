package dns.packets;

import dns.records.AAAARecord;
import dns.records.ARecord;
import dns.records.CnameRecord;
import dns.records.MxRecord;
import dns.records.NsRecord;
import dns.records.TxtRecord;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class DnsEncoder {

    public static byte[] buildResponse(
            DnsPacket request,
            List<DnsRecord> answers,
            int responseCode) throws IOException {

        ByteArrayOutputStream out =
                new ByteArrayOutputStream();

        DnsHeader requestHeader =
                request.getHeader();

        int flags =
                0x8000
                | 0x0400
                | (responseCode & 0x0F);

        // =========================
        // HEADER
        // =========================

        writeShort(
                out,
                requestHeader.getId()
        );

        writeShort(
                out,
                flags
        );

        writeShort(
                out,
                request.getQuestions().size()
        );

        writeShort(
                out,
                answers.size()
        );

        writeShort(out, 0);
        writeShort(out, 0);

        // =========================
        // QUESTIONS
        // =========================

        for (DnsQuestion question :
                request.getQuestions()) {

            writeName(
                    out,
                    question.getName()
            );

            writeShort(
                    out,
                    question.getType()
            );

            writeShort(
                    out,
                    question.getDnsClass()
            );
        }

        // =========================
        // ANSWERS
        // =========================

        for (DnsRecord record : answers) {

            // =====================
            // A
            // =====================

            if (record instanceof ARecord aRecord) {

                writeName(
                        out,
                        record.getName()
                );

                writeShort(out, 1);
                writeShort(out, 1);

                writeInt(
                        out,
                        record.getTtl()
                );

                byte[] address =
                        InetAddress.getByName(
                                aRecord.getAddress()
                        ).getAddress();

                writeShort(
                        out,
                        address.length
                );

                out.write(address);
            }

            // =====================
            // AAAA
            // =====================

            else if (record instanceof AAAARecord aaaaRecord) {

                writeName(
                        out,
                        record.getName()
                );

                writeShort(out, 28);
                writeShort(out, 1);

                writeInt(
                        out,
                        record.getTtl()
                );

                byte[] address =
                        InetAddress.getByName(
                                aaaaRecord.getAddress()
                        ).getAddress();

                writeShort(
                        out,
                        address.length
                );

                out.write(address);
            }

            // =====================
            // CNAME
            // =====================

            else if (record instanceof CnameRecord cnameRecord) {

                writeName(
                        out,
                        record.getName()
                );

                writeShort(out, 5);
                writeShort(out, 1);

                writeInt(
                        out,
                        record.getTtl()
                );

                ByteArrayOutputStream targetOut =
                        new ByteArrayOutputStream();

                writeName(
                        targetOut,
                        cnameRecord.getTarget()
                );

                byte[] target =
                        targetOut.toByteArray();

                writeShort(
                        out,
                        target.length
                );

                out.write(target);
            }

            // =====================
            // NS
            // =====================

            else if (record instanceof NsRecord nsRecord) {

                writeName(
                        out,
                        record.getName()
                );

                writeShort(out, 2);
                writeShort(out, 1);

                writeInt(
                        out,
                        record.getTtl()
                );

                ByteArrayOutputStream targetOut =
                        new ByteArrayOutputStream();

                writeName(
                        targetOut,
                        nsRecord.getTarget()
                );

                byte[] target =
                        targetOut.toByteArray();

                writeShort(
                        out,
                        target.length
                );

                out.write(target);
            }

            // =====================
            // MX
            // =====================

            else if (record instanceof MxRecord mxRecord) {

                writeName(
                        out,
                        record.getName()
                );

                writeShort(out, 15);
                writeShort(out, 1);

                writeInt(
                        out,
                        record.getTtl()
                );

                ByteArrayOutputStream mxData =
                        new ByteArrayOutputStream();

                writeShort(
                        mxData,
                        mxRecord.getPreference()
                );

                writeName(
                        mxData,
                        mxRecord.getExchange()
                );

                byte[] data =
                        mxData.toByteArray();

                writeShort(
                        out,
                        data.length
                );

                out.write(data);
            }

            // =====================
            // TXT
            // =====================

            else if (record instanceof TxtRecord txtRecord) {

                writeName(
                        out,
                        record.getName()
                );

                writeShort(out, 16);
                writeShort(out, 1);

                writeInt(
                        out,
                        record.getTtl()
                );

                byte[] text =
                        txtRecord.getText()
                                .getBytes(
                                        StandardCharsets.UTF_8
                                );

                /*
                 * TXT RDATA is one or more
                 * length-prefixed character strings.
                 */

                ByteArrayOutputStream txtData =
                        new ByteArrayOutputStream();

                txtData.write(text.length);
                txtData.write(text);

                byte[] data =
                        txtData.toByteArray();

                writeShort(
                        out,
                        data.length
                );

                out.write(data);
            }
        }

        return out.toByteArray();
    }

    // =========================
    // DNS NAME
    // =========================

    private static void writeName(
            ByteArrayOutputStream out,
            String name) {

        String cleanName =
                name.endsWith(".")
                        ? name.substring(
                                0,
                                name.length() - 1
                        )
                        : name;

        String[] labels =
                cleanName.split("\\.");

        for (String label : labels) {

            out.write(
                    label.length()
            );

            byte[] bytes =
                    label.getBytes(
                            StandardCharsets.US_ASCII
                    );

            out.writeBytes(bytes);
        }

        out.write(0);
    }

    // =========================
    // 16-BIT INTEGER
    // =========================

    private static void writeShort(
            ByteArrayOutputStream out,
            int value) {

        out.write(
                (value >> 8) & 0xFF
        );

        out.write(
                value & 0xFF
        );
    }

    // =========================
    // 32-BIT INTEGER
    // =========================

    private static void writeInt(
            ByteArrayOutputStream out,
            int value) {

        out.write(
                (value >> 24) & 0xFF
        );

        out.write(
                (value >> 16) & 0xFF
        );

        out.write(
                (value >> 8) & 0xFF
        );

        out.write(
                value & 0xFF
        );
    }
}
