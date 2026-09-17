package dns.records;

import dns.packets.DnsRecord;

public class AAAARecord extends DnsRecord {

    private final String address;

    public AAAARecord(
            String name,
            String address,
            int ttl) {

        super(name, 28, 1, ttl);
        this.address = address;
    }

    public String getAddress() {
        return address;
    }
}
