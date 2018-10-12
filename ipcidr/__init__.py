import re
import struct


class CIDRHelper:
    @staticmethod
    def ip_format_check(ip):
        return re.match(
            r"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            ip)

    @staticmethod
    def masklen_check(masklen):
        return 0 < masklen < 32

    def parse(self, ip, masklen):
        if not self.ip_format_check(ip) or not self.masklen_check(masklen):
            raise Exception

        ips = ip.split(".")
        bin_ip = 0
        for i in ips:
            bin_ip = bin_ip << 8
            bin_ip += int(i)

        mask = (1 << 32) - 1 - ((1 << (32 - masklen)) - 1)

        a, b, c, d = struct.unpack('BBBB', struct.pack('>I', (bin_ip & mask)))
        start_ip = ".".join([str(a), str(b), str(c), str(d)])

        a, b, c, d = struct.unpack('BBBB', struct.pack('>I', (bin_ip & mask) + (2 << (32 - masklen - 1)) - 1))
        end_ip = ".".join([str(a), str(b), str(c), str(d)])
        return start_ip, end_ip


if __name__ == '__main__':
    ch = CIDRHelper()
    print(ch.parse("192.168.223.1", 24))
