import argparse
import asyncio
import base64
import http.client
import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Union
from urllib.parse import urlencode, urlparse

ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL", "")


@dataclass
class Report:
    vendor: str
    link: str
    last_scan: str
    score: str


@dataclass
class Domain(Report):
    creation_date: str
    last_http_certificate: dict
    registrar: str


@dataclass
class FileHash(Report):
    pass


@dataclass
class IPAddress(Report):
    pass


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


async def virustotal(object_type: str, object_identifier: str, api_key: str) -> None:
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
        headers={"x-apikey": api_key},
    )

    if results:
        attributes = results["data"]["attributes"]
        return Domain(
            vendor="VirusTotal",
            link=generate_link(results["data"]["type"], results["data"]["id"]),
            last_scan=datetime.fromtimestamp(
                attributes["last_analysis_date"]
            ).isoformat(),
            score="10/10",
            creation_date=datetime.fromtimestamp(
                attributes["creation_date"]
            ).isoformat(),
            last_http_certificate={
                key: attributes["last_https_certificate"][key]
                for key in ("validity", "subject")
                if key in attributes["last_https_certificate"]
            },
            registrar=attributes["registrar"],
        )

    # if results:
    #     data = results.get("data", {})
    #     attributes = data.get("attributes", {})
    #     last_analysis_results = attributes.get("last_analysis_results", {})
    #     filtered_result = {
    #         "Link": generate_link(data.get("type"), data.get("id")),
    #         "Last analysis": datetime.fromtimestamp(
    #             attributes.get("last_analysis_date")
    #         ),
    #         "Malicious score (vendors)": f"{sum_malicious_verdicts(last_analysis_results)}/{len(last_analysis_results)}",
    #         "Malicious score (community)": f"{attributes.get('total_votes', {}).get('malicious')}/{sum(attributes.get('total_votes', {}).values())}",
    #         "Tags": attributes.get("tags"),
    #         "Categories": set(attributes.get("categories", {}).values()),
    #     }
    #     if data.get("type") == "domain":
    #         filtered_result.update(
    #             {
    #                 "SSL certificate CN": attributes.get("last_https_certificate", {})
    #                 .get("subject", {})
    #                 .get("CN"),
    #             }
    #         )
    #     elif data.get("type") == "file":
    #         signature_info = attributes.get("signature_info", {})
    #         filtered_result.update(
    #             {
    #                 "Type description": attributes.get("type_description"),
    #                 "Size (bytes)": attributes.get("size"),
    #                 "Product": signature_info.get("product"),
    #                 "Description": signature_info.get("description"),
    #                 "File version": signature_info.get("file version"),
    #                 "Original name": signature_info.get("original name"),
    #                 "Copyright": signature_info.get("copyright"),
    #                 "Magic": attributes.get("magic"),
    #             }
    #         )
    #     elif data.get("type") == "ip_address":
    #         filtered_result.update(
    #             {
    #                 "Country": attributes.get("country"),
    #                 "AS owner": attributes.get("as_owner"),
    #                 "SSL certificate CN": attributes.get("last_https_certificate", {})
    #                 .get("subject", {})
    #                 .get("CN"),
    #             }
    #         )
    #     elif data.get("type") == "url":
    #         filtered_result.update(
    #             {
    #                 "URL": attributes.get("url"),
    #                 "Last final URL": attributes.get("last_final_url"),
    #                 "Title": attributes.get("title"),
    #             }
    #         )
    #     return filtered_result


async def main(args: argparse.Namespace) -> None:
    artifact_type = args.type.lower()
    artifact_value = args.value

    if artifact_type == "domain":
        data = await virustotal("domains", artifact_value, VIRUSTOTAL_API_KEY)
        # print(data)
        print(json.dumps(data.__dict__))
    elif artifact_type == "ip":
        print(args)
    elif artifact_type == "hash":
        pass
    else:
        print(f"Artifact type '{artifact_type}' is not supported.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--raw", help="show raw API response")
    parser.add_argument("type", help="type of an artifact")
    parser.add_argument("value", help="value of an artifact")

    asyncio.run(main(parser.parse_args()))
