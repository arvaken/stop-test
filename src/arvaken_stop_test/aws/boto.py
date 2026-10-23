"""AWS's clients, made from your own credentials as the AWS command line finds them. Needs the `aws` extra (boto3)."""
from __future__ import annotations

from arvaken_stop_test.aws.run import Clients


def trail_region(region: str) -> str:
    """Where CloudTrail's event history holds the kit's attach call. IAM is a global service, and in AWS's commercial
    partition its calls are recorded in US East (N. Virginia), never in the run's own region: read in install-test on
    23 October 2026, the run's AttachRolePolicy was in us-east-1's history and not in eu-central-1's. For another
    partition the run's own region is asked, unverified; where nothing is found the kit times from its own clock."""
    return region if region.startswith(("us-gov-", "cn-")) else "us-east-1"


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
                   cloudtrail=session.client("cloudtrail", region_name=trail_region(region), config=config),
                   tagging=make("resourcegroupstaggingapi"), region=region, logs=make("logs"))
