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

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.List;

public class DnsServer {

    private static final int PORT = 8053;
    private static final int BUFFER_SIZE = 512;

    public static void main(String[] args) {

        Zone zone =
                ZoneLoader.loadDefaultZone();

        Resolver resolver =
                new LocalResolver(zone);

        try (DatagramSocket socket =
                     new DatagramSocket(PORT)) {

            System.out.println(
                    "DNS server started."
            );

            System.out.println(
                    "Listening on UDP port " + PORT
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
                            "Query: "
                            + question.getName()
                            + " type="
                            + question.getType()
                    );

                    List<DnsRecord> answers =
                            resolver.resolve(question);

                    int responseCode;

                    if (zone.exists(
                            question.getName())) {

                        // Domain exists
                        responseCode = 0;

                    } else {

                        // Domain does not exist
                        responseCode = 3;
                    }

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

                    if (responseCode == 3) {

                        System.out.println(
                                "Sent NXDOMAIN"
                        );

                    } else {

                        System.out.println(
                                "Sent "
                                + answers.size()
                                + " answer(s)"
                        );
                    }

                } catch (Exception e) {

                    System.err.println(
                            "Failed to process DNS query:"
                    );

                    e.printStackTrace();
                }
            }

        } catch (Exception e) {

            e.printStackTrace();
        }
    }
}
