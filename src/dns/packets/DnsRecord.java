package dns.packets;

public abstract class DnsRecord {

    protected final String name;
    protected final int type;
    protected final int dnsClass;
    protected final int ttl;

    protected DnsRecord(
            String name,
            int type,
            int dnsClass,
            int ttl) {

        this.name = name;
        this.type = type;
        this.dnsClass = dnsClass;
        this.ttl = ttl;
    }

    public String getName() {
        return name;
    }

    public int getType() {
        return type;
    }

    public int getDnsClass() {
        return dnsClass;
    }

    public int getTtl() {
        return ttl;
    }
}
