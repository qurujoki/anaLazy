#!/usr/bin/env python3

import asyncio
import json
import os
from base64 import urlsafe_b64encode
from cmd import Cmd
from configparser import ConfigParser
from datetime import datetime
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

config = ConfigParser()
config.read("anaLazy.cfg")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", config.get("ABUSEIPDB", "api_key"))
VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY", config.get("VIRUSTOTAL", "api_key")
)


class Shell(Cmd):
    def do_domain(self, domain: str) -> None:
        async def run():
            await asyncio.gather(virustotal("domains", domain))

        asyncio.run(run())

    def do_hash(self, hash: str) -> None:
        async def run():
            await asyncio.gather(virustotal("files", hash))

        asyncio.run(run())

    def do_ip(self, ip_address: str) -> None:
        async def run():
            await asyncio.gather(
                abuseipdb(ip_address),
                shodan(ip_address),
                virustotal("ip_addresses", ip_address),
            )

        asyncio.run(run())

    def do_url(self, url: str) -> None:
        async def run():
            await asyncio.gather(urlscan(url), virustotal("urls", url))

        asyncio.run(run())

    def emptyline(self) -> None:
        pass


def print_result_summary(data: dict[str, Any]) -> None:
    key_width = max(len(str(key)) for key in data.keys())
    for key, value in data.items():
        key = key.ljust(key_width)
        if isinstance(value, (list, set)):
            value = ", ".join(str(i) for i in value)
        print(f"{key} : {str(value)}")
    print()


async def abuseipdb(ip_address: str) -> None:
    parameters = urlencode({"ipAddress": ip_address})
    request = Request(f"https://api.abuseipdb.com/api/v2/check?{parameters}")
    request.add_header("Accept", "application/json")
    request.add_header("Key", ABUSEIPDB_API_KEY)

    try:
        data = json.loads(urlopen(request).read())
    except HTTPError as e:
        data = None
        print(e, request.full_url, os.linesep)

    if not data:
        return

    data = data.get("data", {})
    print_result_summary(
        {
            "Full report": f"https://www.abuseipdb.com/check/{data.get('ipAddress')}",
            "Last reported": data.get("lastReportedAt"),
            "Abuse confidence score": f"{data.get('abuseConfidenceScore')}/100",
            "Domain": data.get("domain"),
            "Hostnames": data.get("hostnames"),
            "ISP": data.get("isp"),
            "Country code": data.get("countryCode"),
            "Usage type": data.get("usageType"),
            "Tor node": data.get("isTor"),
        }
    )


async def shodan(ip_address: str) -> None:
    request = Request(f"https://api.shodan.io/shodan/host/{ip_address}")
    try:
        data = json.loads(urlopen(request).read())
    except HTTPError as e:
        data = None
        print(e, request.full_url, os.linesep)

    if not data:
        return

    print_result_summary(
        {
            "Full report": f"https://shodan.io/host/{data.get('ip_str')}",
            "Last udpdated": data.get("last_update"),
            "Tags": data.get("tags"),
            "ISP": data.get("isp"),
            "Ports": data.get("ports"),
            "Hostnames": data.get("hostnames"),
            "Country": data.get("country_name"),
            "Domains": data.get("domains"),
            "Organization": data.get("org"),
        }
    )


async def urlscan(url: str) -> None:
    parsed_url = urlparse(url)
    if parsed_url.netloc:
        domain = parsed_url.netloc
    else:
        domain = parsed_url.path.split("/")[0].replace("www", "")
    search_parameters = urlencode({"q": f"domain:{domain}"})
    search_request = Request(f"https://urlscan.io/api/v1/search?{search_parameters}")
    try:
        related_searches = json.loads(urlopen(search_request).read())
    except HTTPError as e:
        related_searches = None
        print(e, search_request.full_url, os.linesep)

    if not related_searches:
        return

    report_available_for_url = False
    for result in related_searches.get("results", {}):
        report_available_for_url = url in result.get("task", {}).get("url", "")
        if report_available_for_url:
            # use first match because lazy
            result_request = Request(
                f"https://urlscan.io/api/v1/result/{result['_id']}"
            )
            break

    if not report_available_for_url:
        print(
            f"Did not find existing scan results from urlscan.io for URL '{url}'",
            os.linesep,
        )
        return

    try:
        search_result = json.loads(urlopen(result_request).read())
    except HTTPError as e:
        search_result = None
        print(e, result_request.full_url, os.linesep)

    if not search_result:
        print(
            f"Did not find existing scan results from urlscan.io for URL '{url}'",
            os.linesep,
        )
        return
    print_result_summary(
        {
            "Full report": search_result.get("task", {}).get("reportURL"),
            "Submission": search_result.get("task", {}).get("time"),
            "Score": f'{search_result.get("verdicts", {}).get("overall").get("score")}/100',
            "Malicious": search_result.get("verdicts", {})
            .get("overall")
            .get("malicious"),
            "Effective URL": search_result.get("page", {}).get("url"),
            "Categories": search_result.get("verdicts", {})
            .get("overall", {})
            .get("categories"),
            "Brands": search_result.get("verdicts", {})
            .get("overall", {})
            .get("brands"),
            "Tags": search_result.get("verdicts", {}).get("overall", {}).get("tags"),
            "Server": search_result.get("page", {}).get("server"),
            "IP": search_result.get("page", {}).get("ip"),
            "ASN name": search_result.get("page", {}).get("asnname"),
        }
    )


async def virustotal(object_type: str, object_identifier: str) -> None:
    def generate_link(object_type: str, object_id: str) -> str:
        object_type_map = {
            "domain": "domain",
            "file": "file",
            "ip_address": "ip-address",
            "url": "url",
        }
        return (
            f"https://virustotal.com/gui/{object_type_map.get(object_type)}/{object_id}"
        )

    def sum_malicious_verdicts(last_analysis_results: dict[dict[Any, str]]) -> int:
        return len(
            [
                verdict
                for provider in last_analysis_results.keys()
                for verdict in last_analysis_results[provider].values()
                if verdict == "malicious"
            ]
        )

    if object_type == "urls":
        object_identifier = (
            urlsafe_b64encode(object_identifier.encode()).decode().strip("=")
        )

    request = Request(
        f"https://virustotal.com/api/v3/{object_type}/{object_identifier}"
    )
    request.add_header("x-apikey", VIRUSTOTAL_API_KEY)
    try:
        results = json.loads(urlopen(request).read())
    except HTTPError as e:
        results = None
        print(e, request.full_url, os.linesep)

    if not results:
        return

    data = results.get("data", {})
    attributes = data.get("attributes", {})
    last_analysis_results = attributes.get("last_analysis_results", {})
    filtered_result = {
        "Full report": generate_link(data.get("type"), data.get("id")),
        "Last analysis": datetime.fromtimestamp(attributes.get("last_analysis_date")),
        "Malicious score (vendors)": f"{sum_malicious_verdicts(last_analysis_results)}/{len(last_analysis_results)}",
        "Malicious score (community)": f"{attributes.get('total_votes', {}).get('malicious')}/{sum(attributes.get('total_votes', {}).values())}",
        "Tags": attributes.get("tags"),
    }
    if data.get("type") == "domain":
        filtered_result.update(
            {
                "Categories": set(attributes.get("categories", {}).values()),
                "SSL certificate CN": attributes.get("last_https_certificate", {})
                .get("subject", {})
                .get("CN"),
            }
        )
    elif data.get("type") == "file":
        signature_info = attributes.get("signature_info", {})
        filtered_result.update(
            {
                "Type description": attributes.get("type_description"),
                "Size (bytes)": attributes.get("size"),
                "Product": signature_info.get("product"),
                "Description": signature_info.get("description"),
                "File version": signature_info.get("file version"),
                "Original name": signature_info.get("original name"),
                "Copyright": signature_info.get("copyright"),
                "Magic": attributes.get("magic"),
            }
        )
    elif data.get("type") == "ip_address":
        filtered_result.update(
            {
                "Country": attributes.get("country"),
                "AS owner": attributes.get("as_owner"),
                "SSL certificate CN": attributes.get("last_https_certificate", {})
                .get("subject", {})
                .get("CN"),
            }
        )
    elif data.get("type") == "url":
        filtered_result.update(
            {
                "URL": attributes.get("url"),
                "Last final URL": attributes.get("last_final_url"),
                "Title": attributes.get("title"),
            }
        )
    print_result_summary(filtered_result)


def main() -> None:
    shell = Shell()
    shell.prompt = "anaLazy > "
    shell.cmdloop()


if __name__ == "__main__":
    main()
