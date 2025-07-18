---
mapped_pages:
  - https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-metricset-istio-mesh.html
---

% This file is generated! See scripts/docs_collector.py

# Istio mesh metricset [metricbeat-metricset-istio-mesh]

::::{warning}
This functionality is in beta and is subject to change. The design and code is less mature than official GA features and is being provided as-is with no warranties. Beta features are not subject to the support SLA of official GA features.
::::


This is the mesh metricset of the module istio. This metricset collects all Mixer-generated metrics.

## Fields [_fields]

For a description of each field in the metricset, see the [exported fields](/reference/metricbeat/exported-fields-istio.md) section.

Here is an example document generated by this metricset:

```json
{
    "@timestamp": "2019-03-01T08:05:34.853Z",
    "event": {
        "dataset": "istio.mesh",
        "duration": 115000,
        "module": "istio"
    },
    "istio": {
        "mesh": {
            "connection": {
                "security": {
                    "policy": "unknown"
                }
            },
            "destination": {
                "app": "reviews",
                "principal": "unknown",
                "service": {
                    "host": "details.default.svc.cluster.local",
                    "name": "details",
                    "namespace": "default"
                },
                "version": "v1",
                "workload": {
                    "name": "reviews-v1",
                    "namespace": "default"
                }
            },
            "reporter": "source",
            "request": {
                "duration": {
                    "ms": {
                        "bucket": {
                            "+Inf": 1,
                            "10": 1,
                            "100": 1,
                            "1000": 1,
                            "10000": 1,
                            "25": 1,
                            "250": 1,
                            "2500": 1,
                            "5": 0,
                            "50": 1,
                            "500": 1,
                            "5000": 1
                        },
                        "count": 1,
                        "sum": 5.815905
                    }
                },
                "protocol": "http",
                "size": {
                    "bytes": {
                        "bucket": {
                            "+Inf": 1,
                            "1": 1,
                            "10": 1,
                            "100": 1,
                            "1000": 1,
                            "10000": 1,
                            "100000": 1,
                            "1000000": 1,
                            "10000000": 1,
                            "100000000": 1
                        },
                        "count": 1,
                        "sum": 0
                    }
                }
            },
            "requests": 1,
            "response": {
                "code": "200",
                "size": {
                    "bytes": {
                        "bucket": {
                            "+Inf": 1,
                            "1": 0,
                            "10": 0,
                            "100": 0,
                            "1000": 1,
                            "10000": 1,
                            "100000": 1,
                            "1000000": 1,
                            "10000000": 1,
                            "100000000": 1
                        },
                        "count": 1,
                        "sum": 178
                    }
                }
            },
            "source": {
                "app": "productpage",
                "principal": "unknown",
                "version": "v1",
                "workload": {
                    "name": "productpage-v1",
                    "namespace": "default"
                }
            }
        }
    },
    "metricset": {
        "name": "mesh",
        "period": 10000
    },
    "service": {
        "address": "127.0.0.1:55555",
        "type": "istio"
    }
}
```
