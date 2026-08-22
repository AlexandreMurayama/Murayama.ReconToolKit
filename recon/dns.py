import dns.resolver


def enumerate_dns(target: str):
    record_types = ["A", "AAAA", "MX", "NS", "TXT"]

    results = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(target, record_type)

            results[record_type] = [
                answer.to_text()
                for answer in answers
            ]

        except dns.resolver.NoAnswer:
            results[record_type] = []

        except dns.resolver.NXDOMAIN:
            raise ValueError(f"Domain does not exist: {target}")

        except dns.resolver.Timeout:
            results[record_type] = ["DNS query timed out"]

        except dns.resolver.NoNameservers:
            results[record_type] = ["No nameservers available"]

    return results