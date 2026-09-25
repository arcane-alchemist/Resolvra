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

        // =========================
        // A RECORDS
        // =========================

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

        zone.addRecord(
                new ARecord(
                        "ns1.example.local",
                        "192.168.1.11",
                        300
                )
        );

        zone.addRecord(
                new ARecord(
                        "mail.example.local",
                        "192.168.1.12",
                        300
                )
        );

        // =========================
        // AAAA RECORD
        // =========================

        zone.addRecord(
                new AAAARecord(
                        "ipv6.example.local",
                        "2001:db8::1",
                        300
                )
        );

        // =========================
        // CNAME RECORD
        // =========================

        zone.addRecord(
                new CnameRecord(
                        "alias.example.local",
                        "example.local",
                        300
                )
        );

        // =========================
        // NS RECORD
        // =========================

        zone.addRecord(
                new NsRecord(
                        "example.local",
                        "ns1.example.local",
                        300
                )
        );

        // =========================
        // MX RECORD
        // =========================

        zone.addRecord(
                new MxRecord(
                        "example.local",
                        10,
                        "mail.example.local",
                        300
                )
        );

        // =========================
        // TXT RECORD
        // =========================

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
