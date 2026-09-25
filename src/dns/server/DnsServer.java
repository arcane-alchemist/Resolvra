package dns.server;

import dns.packets.DnsEncoder;
import dns.packets.DnsPacket;
import dns.packets.DnsParser;
import dns.packets.DnsQuestion;
import dns.packets.DnsRecord;
import dns.records.MxRecord;
import dns.records.NsRecord;
import dns.resolver.LocalResolver;
import dns.resolver.Resolver;
import dns.zone.Zone;
import dns.zone.ZoneLoader;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class DnsServer {

    private static final int PORT = 8053;
    private static final int BUFFER_SIZE = 512;

    public static void main(String[] args) {

        Zone zone =
                ZoneLoader.loadDefaultZone();

        Resolver resolver =
                new LocalResolver(zone);

        Thread udpThread =
                new Thread(
                        () -> runUdpServer(
                                resolver,
                                zone
                        )
                );

        Thread tcpThread =
                new Thread(
                        () -> runTcpServer(
                                resolver,
                                zone
                        )
                );

        udpThread.start();
        tcpThread.start();

        System.out.println(
                "DNS server started."
        );

        System.out.println(
                "UDP and TCP listening on port "
                + PORT
        );
    }

    // ==================================================
    // UDP SERVER
    // ==================================================

    private static void runUdpServer(
            Resolver resolver,
            Zone zone) {

        try (DatagramSocket socket =
                     new DatagramSocket(PORT)) {

            System.out.println(
                    "UDP listening on port "
                    + PORT
            );

            byte[] buffer =
                    new byte[BUFFER_SIZE];

            while (true) {

                DatagramPacket request =
                        new DatagramPacket(
                                buffer,
                                buffer.length
                        );

                socket.receive(request);

                try {

                    DnsPacket packet =
                            DnsParser.parse(
                                    request.getData(),
                                    request.getLength()
                            );

                    if (packet.getQuestions().isEmpty()) {
                        continue;
                    }

                    DnsQuestion question =
                            packet.getQuestions().get(0);

                    System.out.println(
                            "UDP Query: "
                            + question.getName()
                            + " type="
                            + question.getType()
                    );

                    List<DnsRecord> answers =
                            resolver.resolve(question);

                    List<DnsRecord> authority =
                            buildAuthorityRecords(
                                    zone,
                                    question
                            );

                    List<DnsRecord> additional =
                            buildAdditionalRecords(
                                    zone,
                                    answers,
                                    authority
                            );

                    int responseCode =
                            determineResponseCode(
                                    zone,
                                    question
                            );

                    byte[] response =
                            DnsEncoder.buildResponse(
                                    packet,
                                    answers,
                                    authority,
                                    additional,
                                    responseCode
                            );

                    DatagramPacket reply =
                            new DatagramPacket(
                                    response,
                                    response.length,
                                    request.getAddress(),
                                    request.getPort()
                            );

                    socket.send(reply);

                } catch (Exception e) {

                    System.err.println(
                            "Failed to process UDP query:"
                    );

                    e.printStackTrace();
                }
            }

        } catch (Exception e) {

            System.err.println(
                    "UDP server failed:"
            );

            e.printStackTrace();
        }
    }

    // ==================================================
    // TCP SERVER
    // ==================================================

    private static void runTcpServer(
            Resolver resolver,
            Zone zone) {

        try (ServerSocket serverSocket =
                     new ServerSocket(PORT)) {

            System.out.println(
                    "TCP listening on port "
                    + PORT
            );

            while (true) {

                Socket socket =
                        serverSocket.accept();

                Thread clientThread =
                        new Thread(
                                () -> handleTcpClient(
                                        socket,
                                        resolver,
                                        zone
                                )
                        );

                clientThread.start();
            }

        } catch (Exception e) {

            System.err.println(
                    "TCP server failed:"
            );

            e.printStackTrace();
        }
    }

    // ==================================================
    // TCP CLIENT
    // ==================================================

    private static void handleTcpClient(
            Socket socket,
            Resolver resolver,
            Zone zone) {

        try (socket;
             DataInputStream input =
                     new DataInputStream(
                             socket.getInputStream()
                     );
             DataOutputStream output =
                     new DataOutputStream(
                             socket.getOutputStream()
                     )) {

            /*
             * DNS over TCP starts with a
             * two-byte message length.
             */
            int messageLength =
                    input.readUnsignedShort();

            if (messageLength <= 0) {
                return;
            }

            byte[] requestData =
                    new byte[messageLength];

            input.readFully(requestData);

            DnsPacket packet =
                    DnsParser.parse(
                            requestData,
                            requestData.length
                    );

            if (packet.getQuestions().isEmpty()) {
                return;
            }

            DnsQuestion question =
                    packet.getQuestions().get(0);

            System.out.println(
                    "TCP Query: "
                    + question.getName()
                    + " type="
                    + question.getType()
            );

            List<DnsRecord> answers =
                    resolver.resolve(question);

            List<DnsRecord> authority =
                    buildAuthorityRecords(
                            zone,
                            question
                    );

            List<DnsRecord> additional =
                    buildAdditionalRecords(
                            zone,
                            answers,
                            authority
                    );

            int responseCode =
                    determineResponseCode(
                            zone,
                            question
                    );

            byte[] response =
                    DnsEncoder.buildResponse(
                            packet,
                            answers,
                            authority,
                            additional,
                            responseCode
                    );

            /*
             * DNS over TCP requires the response
             * length before the DNS message.
             */
            output.writeShort(
                    response.length
            );

            output.write(response);

            output.flush();

        } catch (Exception e) {

            System.err.println(
                    "Failed to process TCP query:"
            );

            e.printStackTrace();
        }
    }

    // ==================================================
    // AUTHORITY RECORDS
    // ==================================================

    private static List<DnsRecord> buildAuthorityRecords(
            Zone zone,
            DnsQuestion question) {

        /*
         * Authority records are currently empty.
         *
         * We will use this section later for
         * proper SOA and negative DNS responses.
         */
        return new ArrayList<>();
    }

    // ==================================================
    // ADDITIONAL RECORDS
    // ==================================================

    private static List<DnsRecord> buildAdditionalRecords(
            Zone zone,
            List<DnsRecord> answers,
            List<DnsRecord> authority) {

        List<DnsRecord> additional =
                new ArrayList<>();

        /*
         * Add A records for nameservers referenced
         * by NS records in the answer section.
         */
        for (DnsRecord record : answers) {

            if (record instanceof NsRecord nsRecord) {

                additional.addAll(
                        zone.find(
                                nsRecord.getTarget(),
                                1
                        )
                );
            }
        }

        /*
         * Add A records for nameservers referenced
         * by NS records in the authority section.
         */
        for (DnsRecord record : authority) {

            if (record instanceof NsRecord nsRecord) {

                additional.addAll(
                        zone.find(
                                nsRecord.getTarget(),
                                1
                        )
                );
            }
        }

        /*
         * Add A records for mail servers referenced
         * by MX records.
         */
        for (DnsRecord record : answers) {

            if (record instanceof MxRecord mxRecord) {

                additional.addAll(
                        zone.find(
                                mxRecord.getExchange(),
                                1
                        )
                );
            }
        }

        return additional;
    }

    // ==================================================
    // RESPONSE CODE
    // ==================================================

    private static int determineResponseCode(
            Zone zone,
            DnsQuestion question) {

        if (zone.exists(
                question.getName())) {

            return 0;
        }

        return 3;
    }
}
