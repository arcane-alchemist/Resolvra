package dns.resolver;

import dns.packets.DnsQuestion;
import dns.packets.DnsRecord;

import java.util.List;

public interface Resolver {

    List<DnsRecord> resolve(DnsQuestion question);
}
