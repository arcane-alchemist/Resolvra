package dns.records;

import dns.packets.DnsRecord;

public class ARecord extends DnsRecord {

    private final String address;

    public ARecord(
            String name,
            String address,
            int ttl) {

        super(name, 1, 1, ttl);

        this.address = address;
    }

    public String getAddress() {
        return address;
    }

    @Override
    public String toString() {
        return name + " " + ttl + " IN A " + address;
    }
}
