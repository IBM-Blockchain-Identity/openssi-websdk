### openssi-websdk 1.0.0-alpha
July, 2020

#### Updates

* Support for Invitations added.
* onboardAsTrustAnchor no longer requires admin credentials.
* Some returned objects have experienced structural changes.  This includes (but not limited to):
  * AgentInfo object
  * Credential definitions
  * Credential schemas
* Agents now referenced by id.  Agent names are no longer unique across a whole agency.

#### Deprecated

* You can no longer connect directly to another agent using an agent URL or agent name.
* Filter queries will not support “or” or “not” operators anymore
