package dns.records;

import dns.packets.DnsRecord;

public class TxtRecord extends DnsRecord {

    private final String text;

    public TxtRecord(
            String name,
            String text,
            int ttl) {

        super(name, 16, 1, ttl);
        this.text = text;
    }

    public String getText() {
        return text;
    }
}

