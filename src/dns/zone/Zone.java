package dns.zone;

import dns.packets.DnsRecord;

import java.util.ArrayList;
import java.util.List;

public class Zone {

    private final List<DnsRecord> records = new ArrayList<>();

    public void addRecord(DnsRecord record) {
        records.add(record);
    }

    public List<DnsRecord> find(String name, int type) {

        List<DnsRecord> result = new ArrayList<>();

        for (DnsRecord record : records) {

            if (record.getName().equalsIgnoreCase(name)
                    && record.getType() == type) {

                result.add(record);
            }
        }

        return result;
    }

    public boolean exists(String name) {

        for (DnsRecord record : records) {

            if (record.getName().equalsIgnoreCase(name)) {
                return true;
            }
        }

        return false;
    }
}
