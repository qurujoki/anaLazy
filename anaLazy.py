import asyncio
import base64
import http.client
import json
import os
import readline
import sys
from typing import Any
from urllib.parse import urlencode, urlparse

LOGO = """
 ▄▄▄       ███▄    █  ▄▄▄       ██▓    ▄▄▄      ▒███████▒▓██   ██▓
▒████▄     ██ ▀█   █ ▒████▄    ▓██▒   ▒████▄    ▒ ▒ ▒ ▄▀░ ▒██  ██▒
▒██  ▀█▄  ▓██  ▀█ ██▒▒██  ▀█▄  ▒██░   ▒██  ▀█▄  ░ ▒ ▄▀▒░   ▒██ ██░
░██▄▄▄▄██ ▓██▒  ▐▌██▒░██▄▄▄▄██ ▒██░   ░██▄▄▄▄██   ▄▀▒   ░  ░ ▐██▓░
 ▓█   ▓██▒▒██░   ▓██░ ▓█   ▓██▒░██████▒▓█   ▓██▒▒███████▒  ░ ██▒▓░
 ▒▒   ▓▒█░░ ▒░   ▒ ▒  ▒▒   ▓▒█░░ ▒░▓  ░▒▒   ▓▒█░░▒▒ ▓░▒░▒   ██▒▒▒ 
  ▒   ▒▒ ░░ ░░   ░ ▒░  ▒   ▒▒ ░░ ░ ▒  ░ ▒   ▒▒ ░░░▒ ▒ ░ ▒ ▓██ ░▒░ 
  ░   ▒      ░   ░ ░   ░   ▒     ░ ░    ░   ▒   ░ ░ ░ ░ ░ ▒ ▒ ░░  
      ░  ░         ░       ░  ░    ░  ░     ░  ░  ░ ░     ░ ░     
                                                ░         ░ ░     
"""

EXIT_COMMANDS = ("exit", "quit", "q")

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL", "")


def get_user_input() -> tuple[str, str]:
    try:
        user_input = input("anaLazy > ")
        readline.add_history(user_input)
        user_input = user_input.split(maxsplit=1) or [""]
        _command = user_input[0].lower()
        _value = user_input[1].lower()
        return _command, _value
    except (EOFError, KeyboardInterrupt):
        sys.exit()
    except IndexError:
        if _command in EXIT_COMMANDS:
            sys.exit()
        return get_user_input()


def send_http_request(
    method: str, host: str, url: str, headers: dict = {}, parameters: dict = {}
) -> dict | None:
    connection = http.client.HTTPSConnection(host)
    if parameters:
        url += "?" + urlencode(parameters)
    connection.request(method, url, headers=headers)
    response = connection.getresponse()
    data = response.read()
    connection.close()
    if response.status == 200:
        return json.loads(data.decode())
    print(
        f"\nReceived status code {response.status} from {host}\n{json.dumps(json.loads(data.decode()))}"
    )


async def send_async_http_request(
    method: str, host: str, url: str, headers={}, parameters: dict = {}
) -> dict | None:
    return await asyncio.to_thread(
        send_http_request,
        method=method,
        host=host,
        url=url,
        headers=headers,
        parameters=parameters,
    )


async def abuseipdb(ip_address: str):
    def filter_results(results: dict) -> dict[str, Any] | None:
        data = results.get("data", {})
        return {
            "Link": f"https://www.abuseipdb.com/check/{data.get('ipAddress')}",
            "Abuse confidence score": f"{data.get('abuseConfidenceScore')}/100",
            "Domain": data.get("domain"),
            "Hostnames": ", ".join(data.get("hostnames", [])),
            "ISP": data.get("isp"),
            "Country code": data.get("countryCode"),
            "Usage type": data.get("usageType"),
            "Tor node": str(data.get("isTor")),
        }

    results = await send_async_http_request(
        method="GET",
        host="api.abuseipdb.com",
        url="/api/v2/check",
        headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
        parameters={"ipAddress": ip_address},
    )
    if results:
        return filter_results(results)


async def virustotal(object_type: str, object_identifier: str):
    def filter_results(results: dict) -> dict[str, Any] | None:
        data = results.get("data", {})
        attributes = data.get("attributes", {})
        last_analysis_results = attributes.get("last_analysis_results", {})
        filtered_result = {
            "Link": generate_link(data.get("type"), data.get("id")),
            "Malicious score (vendors)": f"{sum_malicious_verdicts(last_analysis_results)}/{len(last_analysis_results)}",
            "Malicious score (community)": f"{attributes.get('total_votes', {}).get('malicious')}/{sum(attributes.get('total_votes', {}).values())}",
            "Tags": ", ".join(attributes.get("tags", [])),
            "Categories": ", ".join(set(attributes.get("categories", {}).values())),
        }
        if data.get("type") == "domain":
            filtered_result.update(
                {
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
        return filtered_result

    def generate_link(object_type: str, object_id: str) -> str:
        object_type_map = {
            "domain": "domain",
            "file": "hash",
            "ip_address": "ip-address",
            "url": "url",
        }
        return (
            f"https://virustotal.com/gui/{object_type_map.get(object_type)}/{object_id}"
        )

    def sum_malicious_verdicts(last_analysis_results: dict) -> int:
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
            base64.urlsafe_b64encode(object_identifier.encode()).decode().strip("=")
        )

    results = await send_async_http_request(
        method="GET",
        host="virustotal.com",
        url=f"/api/v3/{object_type}/{object_identifier}",
        headers={"x-apikey": VIRUSTOTAL_API_KEY},
    )
    if results:
        return filter_results(results)


async def shodan(search_method: str = "/shodan/host/", search_value: str = ""):
    def filter_results(results: dict) -> dict[str, Any] | None:
        return {
            "Link": f"https://shodan.io/host/{results.get('ip_str')}",
            "Tags": ", ".join(results.get("tags", [])),
            "ISP": results.get("isp"),
            "Ports": ", ".join(str(port) for port in results.get("ports", [])),
            "Hostnames": ", ".join(results.get("hostnames", [])),
            "Country": results.get("country_name"),
            "Domains": ", ".join(results.get("domains", [])),
            "Organization": results.get("org"),
        }

    results = await send_async_http_request(
        method="GET",
        host="api.shodan.io",
        url=f"{search_method}{search_value}",
    )
    if results:
        return filter_results(results)


async def urlscan(url):
    def parse_domain(url: str) -> str:
        parsed_url = urlparse(url)
        if parsed_url.netloc:
            return parsed_url.netloc
        return parsed_url.path.split("/")[0].replace("www", "")

    async def get_searches_for_domain(domain: str) -> dict:
        return await send_async_http_request(
            method="GET",
            host="urlscan.io",
            url="/api/v1/search/",
            parameters={"q": f"domain:{domain}"},
        )

    async def get_search_results(result_id: str) -> dict:
        return await send_async_http_request(
            method="GET",
            host="urlscan.io",
            url=f"/api/v1/result/{result_id}",
        )

    def filter_results(results: dict) -> dict[str, Any]:
        return {
            "Link": results.get("task", {}).get("reportURL"),
            "Effective URL": results.get("page", {}).get("url"),
            "Score": f'{results.get("verdicts", {}).get("overall").get("score")}/100',
            "Malicious": results.get("verdicts", {}).get("overall").get("malicious"),
            "Categories": ", ".join(
                results.get("verdicts", {}).get("overall", {}).get("categories")
            ),
            "Brands": ", ".join(
                results.get("verdicts", {}).get("overall", {}).get("brands")
            ),
            "Tags": ", ".join(
                results.get("verdicts", {}).get("overall", {}).get("tags")
            ),
            "Server": results.get("page", {}).get("server"),
            "IP": results.get("page", {}).get("ip"),
            "ASN name": results.get("page", {}).get("asnname"),
        }

    related_searches = await get_searches_for_domain(parse_domain(url))
    if related_searches:
        for result in related_searches.get("results", {}):
            results_available_for_url = url in result.get("task", {}).get("url", "")
            if results_available_for_url:
                return filter_results(await get_search_results(result.get("_id")))


def print_table(data):
    key_width = max(len(str(key)) for key in data.keys())
    print(f"\n{data.pop('Link')}\n")
    for key, value in data.items():
        key = str(key).ljust(key_width)
        value = str(value)
        if value:
            print(f"  {key} : {value}")


async def main():
    while True:
        _command, _value = get_user_input()
        tasks = []
        if _command == "ip":
            tasks.extend(
                [
                    abuseipdb(_value),
                    virustotal("ip_addresses", _value),
                    shodan(search_value=_value),
                ]
            )
        elif _command == "domain":
            tasks.extend([virustotal("domains", _value)])
        elif _command == "url":
            tasks.extend([virustotal("urls", _value), urlscan(_value)])
        elif _command == "hash":
            tasks.extend([virustotal("files", _value)])

        for task in asyncio.as_completed(tasks):
            results = await task
            if results:
                print_table(results)
        print()


if __name__ == "__main__":
    print(LOGO)
    asyncio.run(main())
