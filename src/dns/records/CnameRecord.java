package dns.records;

import dns.packets.DnsRecord;

public class CnameRecord extends DnsRecord {

    private final String target;

    public CnameRecord(
            String name,
            String target,
            int ttl) {

        super(name, 5, 1, ttl);
        this.target = target;
    }

    public String getTarget() {
        return target;
    }
}
