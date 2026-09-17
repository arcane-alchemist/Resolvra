package dns.packets;

public class DnsHeader {

    private final int id;
    private final int flags;
    private final int questionCount;
    private final int answerCount;
    private final int authorityCount;
    private final int additionalCount;

    public DnsHeader(
            int id,
            int flags,
            int questionCount,
            int answerCount,
            int authorityCount,
            int additionalCount) {

        this.id = id;
        this.flags = flags;
        this.questionCount = questionCount;
        this.answerCount = answerCount;
        this.authorityCount = authorityCount;
        this.additionalCount = additionalCount;
    }

    public int getId() {
        return id;
    }

    public int getFlags() {
        return flags;
    }

    public int getQuestionCount() {
        return questionCount;
    }

    public int getAnswerCount() {
        return answerCount;
    }

    public int getAuthorityCount() {
        return authorityCount;
    }

    public int getAdditionalCount() {
        return additionalCount;
    }

    @Override
    public String toString() {
        return "DnsHeader{" +
                "id=" + id +
                ", flags=0x" + String.format("%04X", flags) +
                ", questionCount=" + questionCount +
                ", answerCount=" + answerCount +
                ", authorityCount=" + authorityCount +
                ", additionalCount=" + additionalCount +
                '}';
    }
}
