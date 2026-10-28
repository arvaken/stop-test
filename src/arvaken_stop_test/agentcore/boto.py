"""AWS's clients for a run on AgentCore, made from your own credentials as the AWS command line finds them. Needs the
`aws` extra (boto3).

The calls to the agent are made once each, never again by the SDK: a call made again would hide a refusal, or time it
late. They overlap, so the client keeps a connection for each thread that makes them (run.NEW_CALL_WORKERS). The
running session's stream sends an event about every second, so a read that waits READ_TIMEOUT seconds has lost it.
"""
from __future__ import annotations

from arvaken_stop_test.agentcore.run import NEW_CALL_WORKERS, Clients
from arvaken_stop_test.aws.boto import trail_region

READ_TIMEOUT = 30


def clients_for(region: str) -> Clients:
    try:
        import boto3
        import botocore.config
    except ImportError as e:  # pragma: no cover - said, with the fix
        raise SystemExit("The AWS module needs boto3: install the kit with its aws extra, as its README says.") from e
    config = botocore.config.Config(retries={"max_attempts": 3, "mode": "standard"})
    once = botocore.config.Config(retries={"total_max_attempts": 1, "mode": "standard"}, connect_timeout=5,
                                  read_timeout=READ_TIMEOUT, max_pool_connections=NEW_CALL_WORKERS + 8)
    session = boto3.Session(region_name=region)
    make = lambda name: session.client(name, config=config)  # noqa: E731
    return Clients(iam=make("iam"), s3=make("s3"), control=make("bedrock-agentcore-control"),
                   data=session.client("bedrock-agentcore", config=once), cloudtrail=make("cloudtrail"),
                   iam_trail=session.client("cloudtrail", region_name=trail_region(region), config=config),
                   tagging=make("resourcegroupstaggingapi"), region=region, logs=make("logs"), sts=make("sts"))
