# Arvaken stop test

**In development, not yet released.**

The stop test is a kit you run yourself, in your own cloud account, with your own credentials. It deploys a test
agent of its own, fires the stop you have declared on that test agent alone, and times what actually stops. When it
finishes, it removes the stop it fired and everything it made.

Arvaken runs nothing in your account. To time the paths that leave your cloud's own permissions, the test agent calls
a test endpoint Arvaken runs; those calls carry nothing of your account, and the endpoint keeps nothing. Nothing of
your account leaves it unless you choose to submit a result, under the kit's submission terms, which are published
with the kit's first release.

AWS comes first. Google Cloud and Azure follow.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
