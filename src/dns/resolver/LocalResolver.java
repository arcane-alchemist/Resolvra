package dns.resolver;

import dns.packets.DnsQuestion;
import dns.packets.DnsRecord;
import dns.zone.Zone;

import java.util.List;

public class LocalResolver implements Resolver {

    private final Zone zone;

    public LocalResolver(Zone zone) {
        this.zone = zone;
    }

    @Override
    public List<DnsRecord> resolve(DnsQuestion question) {

        return zone.find(
                question.getName(),
                question.getType()
        );
    }
}
