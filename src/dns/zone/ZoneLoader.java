package dns.zone;

import dns.records.ARecord;

public class ZoneLoader {

    public static Zone loadDefaultZone() {

        Zone zone = new Zone();

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

        return zone;
    }
}
