"""AWS's clients, made from your own credentials as the AWS command line finds them. Needs the `aws` extra (boto3)."""
from __future__ import annotations

from arvaken_stop_test.aws.run import Clients


def clients_for(region: str) -> Clients:
    try:
        import boto3
        import botocore.config
    except ImportError as e:  # pragma: no cover - said, with the fix
        raise SystemExit("The AWS module needs boto3: pip install 'arvaken-stop-test[aws]'") from e
    config = botocore.config.Config(retries={"max_attempts": 3, "mode": "standard"})
    session = boto3.Session(region_name=region)
    make = lambda name: session.client(name, config=config)  # noqa: E731
    return Clients(cloudformation=make("cloudformation"), iam=make("iam"), lambda_=make("lambda"), s3=make("s3"),
                   cloudtrail=make("cloudtrail"), tagging=make("resourcegroupstaggingapi"), region=region)
