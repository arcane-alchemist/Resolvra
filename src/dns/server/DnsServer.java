package dns.server;

import dns.packets.DnsEncoder;
import dns.packets.DnsPacket;
import dns.packets.DnsParser;
import dns.packets.DnsQuestion;
import dns.packets.DnsRecord;
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

                    int responseCode =
                            determineResponseCode(
                                    zone,
                                    question
                            );

                    byte[] response =
                            DnsEncoder.buildResponse(
                                    packet,
                                    answers,
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

            int responseCode =
                    determineResponseCode(
                            zone,
                            question
                    );

            byte[] response =
                    DnsEncoder.buildResponse(
                            packet,
                            answers,
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
