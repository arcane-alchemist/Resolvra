package dns.packets;

public class DnsQuestion {

    private final String name;
    private final int type;
    private final int dnsClass;

    public DnsQuestion(String name, int type, int dnsClass) {
        this.name = name;
        this.type = type;
        this.dnsClass = dnsClass;
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

    @Override
    public String toString() {
        return "DnsQuestion{" +
                "name='" + name + '\'' +
                ", type=" + type +
                ", dnsClass=" + dnsClass +
                '}';
    }
}
