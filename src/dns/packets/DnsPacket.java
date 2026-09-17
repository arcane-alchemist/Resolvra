package dns.packets;

import java.util.ArrayList;
import java.util.List;

public class DnsPacket {

    private final DnsHeader header;
    private final List<DnsQuestion> questions;
    private final List<DnsRecord> answers;

    public DnsPacket(
            DnsHeader header,
            List<DnsQuestion> questions,
            List<DnsRecord> answers) {

        this.header = header;
        this.questions = questions;
        this.answers = answers;
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
}
