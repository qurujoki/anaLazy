import asyncio
import base64
import http.client
import json
import os
import readline
import sys
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlencode, urlparse

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL", "")

HELP = """
Usage:
    anaLazy > COMMAND VALUE [OPTIONS]

Commands:
    domain          Check existing scan results for given domain.
    hash            Check existing scan results for given hash.
    ip              Check existing scan results for given IP.
    url             Check existing scan results for given URL.
    help            Print this message.
    exit/quit/q     Exit the program. CTRL-D and CTRL-C also exit.

Options:
    -r, --raw       Print results of a command in raw JSON format.

Other:
    Command history is also available via `readline` during runtime. Press up/down arrows to circle through the command history.
"""

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

print_raw = False


def get_user_input() -> tuple[str, str, Optional[str | None]]:
    try:
        user_input = input("anaLazy > ")
        readline.add_history(user_input)
        user_input = user_input.split() or [""]
        _command = user_input[0].lower()
        _value = user_input[1].lower()
        try:
            options = user_input[2].lower()
        except IndexError:
            return (_command, _value, "")
        return (_command, _value, options)
    except (EOFError, KeyboardInterrupt):
        sys.exit()
    except IndexError:
        if _command in ("exit", "quit", "q"):
            sys.exit()
        elif _command == "help":
            print(HELP)
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
        f"\n[!] Received status code {response.status} from {host}\n{json.dumps(json.loads(data.decode()))}"
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


def print_result_summary(data: dict[str, Any]) -> None:
    key_width = max(len(str(key)) for key in data.keys())
    print(f"\n{data.pop('Link')}\n")
    for key, value in data.items():
        key = key.ljust(key_width)
        if isinstance(value, (list, set)):
            value = ", ".join(str(i) for i in value)
        if value and not isinstance(value, dict):
            print(f"\x20\x20{key} : {str(value)}")


async def abuseipdb(ip_address: str) -> None:
    results = await send_async_http_request(
        method="GET",
        host="api.abuseipdb.com",
        url="/api/v2/check",
        headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
        parameters={"ipAddress": ip_address},
    )
    if results and print_raw:
        print(f"\n{json.dumps(results)}\n")
    elif results:
        data = results.get("data", {})
        print_result_summary(
            {
                "Link": f"https://www.abuseipdb.com/check/{data.get('ipAddress')}",
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


async def shodan(
    search_value: str | None,
    search_method: str = "/shodan/host/",
) -> None:
    results = await send_async_http_request(
        method="GET",
        host="api.shodan.io",
        url=f"{search_method}{search_value}",
    )
    if results and print_raw:
        print(f"\n{json.dumps(results)}\n")
    elif results:
        print_result_summary(
            {
                "Link": f"https://shodan.io/host/{results.get('ip_str')}",
                "Last udpdated": results.get("last_update"),
                "Tags": results.get("tags"),
                "ISP": results.get("isp"),
                "Ports": results.get("ports"),
                "Hostnames": results.get("hostnames"),
                "Country": results.get("country_name"),
                "Domains": results.get("domains"),
                "Organization": results.get("org"),
            }
        )


async def urlscan(url: str) -> None:
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

    related_searches = await get_searches_for_domain(parse_domain(url))
    if related_searches:
        search_result = None
        for result in related_searches.get("results", {}):
            results_available_for_url = url in result.get("task", {}).get("url", "")
            if results_available_for_url:
                search_result = await get_search_results(result.get("_id"))

    if not search_result:
        print(f"\n[!] Did not find existing scan results from urlscan.io.")
    if search_result and print_raw:
        print(f"\n{json.dumps(search_result)}\n")
    elif search_result:
        print_result_summary(
            {
                "Link": search_result.get("task", {}).get("reportURL"),
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
                "Tags": search_result.get("verdicts", {})
                .get("overall", {})
                .get("tags"),
                "Server": search_result.get("page", {}).get("server"),
                "IP": search_result.get("page", {}).get("ip"),
                "ASN name": search_result.get("page", {}).get("asnname"),
            }
        )


async def virustotal(object_type: str, object_identifier: str) -> None:
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
            base64.urlsafe_b64encode(object_identifier.encode()).decode().strip("=")
        )

    results = await send_async_http_request(
        method="GET",
        host="virustotal.com",
        url=f"/api/v3/{object_type}/{object_identifier}",
        headers={"x-apikey": VIRUSTOTAL_API_KEY},
    )
    if results and print_raw:
        print(f"\n{json.dumps(results)}\n")
    elif results:
        data = results.get("data", {})
        attributes = data.get("attributes", {})
        last_analysis_results = attributes.get("last_analysis_results", {})
        filtered_result = {
            "Link": generate_link(data.get("type"), data.get("id")),
            "Last analysis": datetime.fromtimestamp(
                attributes.get("last_analysis_date")
            ),
            "Malicious score (vendors)": f"{sum_malicious_verdicts(last_analysis_results)}/{len(last_analysis_results)}",
            "Malicious score (community)": f"{attributes.get('total_votes', {}).get('malicious')}/{sum(attributes.get('total_votes', {}).values())}",
            "Tags": attributes.get("tags"),
            "Categories": set(attributes.get("categories", {}).values()),
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
        print_result_summary(filtered_result)


async def main() -> None:
    global print_raw
    while True:
        _command, _value, options = get_user_input()

        if "-r" in options:
            print_raw = True

        tasks = []
        if _command == "domain":
            tasks.extend([virustotal("domains", _value)])
        if _command == "hash":
            tasks.extend([virustotal("files", _value)])
        if _command == "ip":
            tasks.extend(
                [abuseipdb(_value), shodan(_value), virustotal("ip_addresses", _value)]
            )
        if _command == "url":
            tasks.extend([urlscan(_value), virustotal("urls", _value)])

        await asyncio.gather(*tasks)
        print_raw = False
        print()


if __name__ == "__main__":
    print(LOGO)
    asyncio.run(main())
