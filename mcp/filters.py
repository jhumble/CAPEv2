# Configuration for MCP server search filters
# You can modify this dictionary to include or exclude specific fields in the lean report
# Injested by Agents to give a quick overview

lean_search_filters = {
    "info": 1,
    "virustotal_summary": 1,
    "detections.family": 1,
    "malfamily": 1,
    "malfamily_tag": 1,
    "malscore": 1,
    "network.pcap_sha256": 1,
    "network.domains.domain": 1,
    "network.http.uri": 1,
    "signatures.name": 1,
    "signatures.description": 1,
    "signatures.severity": 1,
    # LOCAL PATCH: upstream has "CAPE": 1, which pulls every unpacked payload with its
    # full `data` and `strings` -- 668 KB on a single ScreenConnect run. That is not
    # "lean" and it exceeds the MCP response limit, so the report is unusable anyway.
    #
    # Projecting payload SUBFIELDS is not an option either, and the reason is not
    # obvious: CAPE normalizes NORMALIZED_FILE_FIELDS ("target.file", "dropped",
    # "CAPE.payloads", "procdump", "procmemory") out into the shared `files` collection
    # and re-merges them on read via the denormalize_files hook, which keys off
    # `file_ref` on each entry. A projection that omits `file_ref` silently skips the
    # merge -- you get the few inline fields and NO sha256, NO cape_yara, with no error.
    # Including `file_ref` merges the whole file doc back and we are at 668 KB again.
    # So for these fields it is all or nothing; take nothing and read payload YARA from
    # the payloadfiles artifact or a direct `files` query instead.
    #
    # `CAPE.configs` is NOT a normalized field, so it projects cleanly and is cheap.
    "CAPE.configs": 1,
    "behavior.summary.mutexes": 1,
    "behavior.summary.executed_commands": 1,
    "mlist_cnt": 1,
    "f_mlist_cnt": 1,
    "target.file.clamav": 1,
    "target.file.sha256": 1,
    "suri_tls_cnt": 1,
    "suri_alert_cnt": 1,
    "suri_http_cnt": 1,
    "suri_file_cnt": 1,
    "trid": 1,
    "_id": 0,
}
