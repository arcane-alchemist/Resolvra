package dns.zone;

import dns.records.AAAARecord;
import dns.records.ARecord;
import dns.records.CnameRecord;
import dns.records.MxRecord;
import dns.records.NsRecord;
import dns.records.TxtRecord;

public class ZoneLoader {

    public static Zone loadDefaultZone() {

        Zone zone = new Zone();

        // A
        zone.addRecord(
                new ARecord(
                        "example.local",
                        "192.168.1.10",
                        300
                )
        );

        zone.addRecord(
                new ARecord(
                        "www.example.local",
                        "192.168.1.10",
                        300
                )
        );

        // AAAA
        zone.addRecord(
                new AAAARecord(
                        "ipv6.example.local",
                        "2001:db8::1",
                        300
                )
        );

        // CNAME
        zone.addRecord(
                new CnameRecord(
                        "alias.example.local",
                        "example.local",
                        300
                )
        );

        // NS
        zone.addRecord(
                new NsRecord(
                        "example.local",
                        "ns1.example.local",
                        300
                )
        );

        // MX
        zone.addRecord(
                new MxRecord(
                        "example.local",
                        10,
                        "mail.example.local",
                        300
                )
        );

        // TXT
        zone.addRecord(
                new TxtRecord(
                        "example.local",
                        "Hello from Resolvra",
                        300
                )
        );

        return zone;
    }
}
