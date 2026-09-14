from integrations.netdata_ringdown_otlp import build_payload


def test_netdata_transition_maps_to_bounded_otlp_log():
    payload = build_payload([
        "sysadmin", "monitored-host.example.test", "used_swap", "system.swap",
        "CRITICAL", "WARNING", "91.2", "%", "System", "system.swap",
        "memory", "System", "42", "7", "transition-1", "1788930000",
        "91.2%",
    ], now_ns=1)

    group = payload["resourceLogs"][0]
    resource = {
        item["key"]: item["value"]["stringValue"]
        for item in group["resource"]["attributes"]
    }
    assert resource == {
        "service.name": "netdata",
        "service.instance.id": "monitored-host.example.test",
        "host.name": "monitored-host.example.test",
    }

    record = group["scopeLogs"][0]["logRecords"][0]
    assert record["severityNumber"] == 18
    assert record["severityText"] == "CRITICAL"
    assert record["timeUnixNano"] == "1788930000000000000"
    assert record["body"]["stringValue"] == (
        "Netdata alarm used_swap WARNING -> CRITICAL on system.swap: 91.2%"
    )
    attributes = {
        item["key"]: item["value"]["stringValue"]
        for item in record["attributes"]
    }
    assert attributes["event"] == "netdata.alarm"
    assert attributes["netdata.recipient"] == "sysadmin"
    assert attributes["netdata.alarm.name"] == "used_swap"
    assert attributes["netdata.component"] == "memory"
