package dns.packets;

import java.util.List;

public class DnsPacket {

    private final DnsHeader header;

    private final List<DnsQuestion> questions;

    private final List<DnsRecord> answers;

    private final List<DnsRecord> authority;

    private final List<DnsRecord> additional;

    public DnsPacket(
            DnsHeader header,
            List<DnsQuestion> questions,
            List<DnsRecord> answers,
            List<DnsRecord> authority,
            List<DnsRecord> additional) {

        this.header = header;
        this.questions = questions;
        this.answers = answers;
        this.authority = authority;
        this.additional = additional;
    }

    public DnsHeader getHeader() {
        return header;
    }

    public List<DnsQuestion> getQuestions() {
        return questions;
    }

    public List<DnsRecord> getAnswers() {
        return answers;
    }

    public List<DnsRecord> getAuthority() {
        return authority;
    }

    public List<DnsRecord> getAdditional() {
        return additional;
    }
}
