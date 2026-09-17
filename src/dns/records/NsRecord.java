package dns.records;

import dns.packets.DnsRecord;

public class NsRecord extends DnsRecord {

    private final String target;

    public NsRecord(
            String name,
            String target,
            int ttl) {

        super(name, 2, 1, ttl);
        this.target = target;
    }

    public String getTarget() {
        return target;
    }
}
