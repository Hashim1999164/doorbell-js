# Contributing

I care about the signature checks more than about extra providers.

If you add a provider, bring:

1. A test signed with `node:crypto`, not with our own `sign*` helper
2. The raw-body footgun, if that provider has one
3. An error string a tired human can read at 1am

Do not add a framework wrapper unless the framework eats the body in a special way.

No CLA. MIT.
