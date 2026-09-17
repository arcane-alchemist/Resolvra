package dns.records;

import dns.packets.DnsRecord;

public class MxRecord extends DnsRecord {

    private final int preference;
    private final String exchange;

    public MxRecord(
            String name,
            int preference,
            String exchange,
            int ttl) {

        super(name, 15, 1, ttl);

        this.preference = preference;
        this.exchange = exchange;
    }

    public int getPreference() {
        return preference;
    }

    public String getExchange() {
        return exchange;
    }
}
