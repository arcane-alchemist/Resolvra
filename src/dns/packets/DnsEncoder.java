package dns.packets;

import dns.records.AAAARecord;
import dns.records.ARecord;
import dns.records.CnameRecord;
import dns.records.MxRecord;
import dns.records.NsRecord;
import dns.records.TxtRecord;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class DnsEncoder {

    public static byte[] buildResponse(
            DnsPacket request,
            List<DnsRecord> answers,
            int responseCode) throws IOException {

        DnsPacketWriter writer =
                new DnsPacketWriter();

        DnsHeader requestHeader =
                request.getHeader();

        /*
         * QR = 1
         * AA = 1
         * RCODE = responseCode
         */
        int flags =
                0x8000
                | 0x0400
                | (responseCode & 0x0F);

        // =========================
        // HEADER
        // =========================

        writer.writeShort(
                requestHeader.getId()
        );

        writer.writeShort(flags);

        writer.writeShort(
                request.getQuestions().size()
        );

        writer.writeShort(
                answers.size()
        );

        writer.writeShort(0); // Authority
        writer.writeShort(0); // Additional

        // =========================
        // QUESTIONS
        // =========================

        for (DnsQuestion question :
                request.getQuestions()) {

            writer.writeName(
                    question.getName()
            );

            writer.writeShort(
                    question.getType()
            );

            writer.writeShort(
                    question.getDnsClass()
            );
        }

        // =========================
        // ANSWERS
        // =========================

        for (DnsRecord record : answers) {

            // =========================
            // A
            // =========================

            if (record instanceof ARecord aRecord) {

                writer.writeName(
                        record.getName()
                );

                writer.writeShort(1); // A
                writer.writeShort(1); // IN

                writer.writeInt(
                        record.getTtl()
                );

                byte[] address =
                        InetAddress.getByName(
                                aRecord.getAddress()
                        ).getAddress();

                writer.writeShort(
                        address.length
                );

                writer.writeBytes(address);
            }

            // =========================
            // AAAA
            // =========================

            else if (
                    record instanceof AAAARecord aaaaRecord
            ) {

                writer.writeName(
                        record.getName()
                );

                writer.writeShort(28); // AAAA
                writer.writeShort(1);  // IN

                writer.writeInt(
                        record.getTtl()
                );

                byte[] address =
                        InetAddress.getByName(
                                aaaaRecord.getAddress()
                        ).getAddress();

                writer.writeShort(
                        address.length
                );

                writer.writeBytes(address);
            }

            // =========================
            // CNAME
            // =========================

            else if (
                    record instanceof CnameRecord cnameRecord
            ) {

                writer.writeName(
                        record.getName()
                );

                writer.writeShort(5); // CNAME
                writer.writeShort(1); // IN

                writer.writeInt(
                        record.getTtl()
                );

                /*
                 * Reserve two bytes for RDLENGTH.
                 */
                int rdLengthPosition =
                        writer.reserveShort();

                int rdataStart =
                        writer.position();

                /*
                 * Write the target directly into
                 * the final packet.
                 *
                 * This allows compression pointers
                 * to use absolute packet offsets.
                 */
                writer.writeName(
                        cnameRecord.getTarget()
                );

                int rdLength =
                        writer.position()
                        - rdataStart;

                writer.setShort(
                        rdLengthPosition,
                        rdLength
                );
            }

            // =========================
            // NS
            // =========================

            else if (
                    record instanceof NsRecord nsRecord
            ) {

                writer.writeName(
                        record.getName()
                );

                writer.writeShort(2); // NS
                writer.writeShort(1); // IN

                writer.writeInt(
                        record.getTtl()
                );

                int rdLengthPosition =
                        writer.reserveShort();

                int rdataStart =
                        writer.position();

                writer.writeName(
                        nsRecord.getTarget()
                );

                int rdLength =
                        writer.position()
                        - rdataStart;

                writer.setShort(
                        rdLengthPosition,
                        rdLength
                );
            }

            // =========================
            // MX
            // =========================

            else if (
                    record instanceof MxRecord mxRecord
            ) {

                writer.writeName(
                        record.getName()
                );

                writer.writeShort(15); // MX
                writer.writeShort(1);  // IN

                writer.writeInt(
                        record.getTtl()
                );

                int rdLengthPosition =
                        writer.reserveShort();

                int rdataStart =
                        writer.position();

                /*
                 * MX preference
                 */
                writer.writeShort(
                        mxRecord.getPreference()
                );

                /*
                 * MX exchange name.
                 */
                writer.writeName(
                        mxRecord.getExchange()
                );

                int rdLength =
                        writer.position()
                        - rdataStart;

                writer.setShort(
                        rdLengthPosition,
                        rdLength
                );
            }

            // =========================
            // TXT
            // =========================

            else if (
                    record instanceof TxtRecord txtRecord
            ) {

                writer.writeName(
                        record.getName()
                );

                writer.writeShort(16); // TXT
                writer.writeShort(1);  // IN

                writer.writeInt(
                        record.getTtl()
                );

                byte[] text =
                        txtRecord.getText()
                                .getBytes(
                                        StandardCharsets.UTF_8
                                );

                /*
                 * TXT RDATA consists of a
                 * length-prefixed character string.
                 */
                int rdLength =
                        1 + text.length;

                writer.writeShort(
                        rdLength
                );

                writer.writeByte(
                        text.length
                );

                writer.writeBytes(text);
            }
        }

        return writer.toByteArray();
    }
}
