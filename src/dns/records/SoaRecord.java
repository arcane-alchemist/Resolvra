package dns.records;

import dns.packets.DnsRecord;

public class SoaRecord extends DnsRecord {

    private final String primaryNameServer;
    private final String responsibleMailbox;
    private final long serial;
    private final long refresh;
    private final long retry;
    private final long expire;
    private final long minimum;

    public SoaRecord(
            String name,
            String primaryNameServer,
            String responsibleMailbox,
            long serial,
            long refresh,
            long retry,
            long expire,
            long minimum,
            int ttl) {

        super(name, 6, 1, ttl);

        this.primaryNameServer = primaryNameServer;
        this.responsibleMailbox = responsibleMailbox;
        this.serial = serial;
        this.refresh = refresh;
        this.retry = retry;
        this.expire = expire;
        this.minimum = minimum;
    }

    public String getPrimaryNameServer() {
        return primaryNameServer;
    }

    public String getResponsibleMailbox() {
        return responsibleMailbox;
    }

    public long getSerial() {
        return serial;
    }

    public long getRefresh() {
        return refresh;
    }

    public long getRetry() {
        return retry;
    }

    public long getExpire() {
        return expire;
    }

    public long getMinimum() {
        return minimum;
    }
}
