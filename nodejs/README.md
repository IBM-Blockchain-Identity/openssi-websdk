[![npm version](https://badge.fury.io/js/openssi-websdk.svg)](https://badge.fury.io/js/openssi-websdk)

# openssi-websdk

This SDK wraps calls to IBM Cloud Agent API in a set of javascript functions.

## Installation

Save `openssi-websdk` as a dependency of your Node.js project:

```
npm install --save openssi-websdk
```

## Table of Contents

- [Using Promises](#using-promises)
- [Getting started](#getting-started)
- [Connecting with other agents](#connecting-with-other-agents)
    - [Sending a connection offer](#sending-a-connection-offer)
    - [Accepting incoming connection offers](#accepting-incoming-connection-offers)
- [Issuing credentials](#issuing-credentials)
    - [Checking your agent's role](#checking-your-agents-role)
    - [Publishing a credential schema](#publishing-a-credential-schema)
    - [Publishing a credential definition](#publishing-a-credential-definition)
    - [Offering credentials](#offering-credentials)
    - [Accepting offered credentials](#accepting-offered-credentials)
- [Verifying](#verifying)
    - [Publishing a proof schema](#publishing-a-proof-schema)
    - [Requesting verification](#requesting-verification)
    - [Responding to proof requests](#responding-to-proof-requests)
    - [Checking the values in a proof](#checking-the-values-in-a-proof)
- [More information](#more-information)

## Using Promises

Functions that involve calls to the cloud agent are `async` functions, meaning that they return [Promises](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise)
You can call these functions from an `async` context as follows:

```javascript
const agent_info = await agent.getIdentity();
console.log(`Agent Info: ${JSON.stringify(agent_info, 0, 1)}`)
```

or from a non`async` context:

```javascript
agent.getIdentity().then((agent_info) => {
    console.log(`Agent Info: ${JSON.stringify(agent_info, 0, 1)}`)
});
```

## Getting started

Create an instance of `Agent` and connect to your cloud agent:

```javascript
const Agent = require('openssi-websdk').Agent;

const account_url = 'https://myaccount.example.com';
const agent_name = 'my_agent';
const agent_password = 'my_password';

const agent = new Agent(account_url, agent_name, agent_password);

(async () => {
	// Check the username and password by hitting the API
    const agentInfo = await agent.getIdentity();
    console.log(`Agent info: ${JSON.stringify(agentInfo, 0, 1)}`)
})
````

## Connecting with other agents

In order to interact with other agents to issue credentials, request verifications, etc., you must first establish a secure connection with those agents.

### Sending a connection offer

Create a `Connection` for another agent with the state `outbound_offer` and wait for it to enter the
`connected` state:

```javascript
const to = {
	url: 'https://theiragent:@theiraccount.example.com'
};

const connection_offer = await agent.sendConnectionOffer(to);
const accepted_connection = await agent.waitForConnection(connection_offer.id);
```
### Accepting incoming connection offers

Get a list of connections with the state `inbound_offer` and change their state to `connected`

```javascript
const opts = {
	state: 'inbound_offer'
};
const inbound_offers = await agent.getConnections(opts);

for (const index in inbound_offers) {
	const accepted_connection = await agent.acceptConnectionOffer(inbound_offers[index].id);
}
```

## Issuing credentials

Once you have a `Connection` to another agent, you can offer `Credentials` over that connection.

### Checking your agent's role

In order to issue credentials, you will need write access to the ledger.  This is only possible if your agent is a
`TRUST_ANCHOR`.

```javascript
const agent_info = await agent.getIdentity();

console.log(agent_info.role);

if (role !== 'TRUST_ANCHOR') {
	
	// Your admin will be the first agent that was created on your account 
	const agent_admin_name = 'my_admin';
	const agent_admin_password = 'my_admin_password';
	
	const updated_agent = await agent.onboardAsTrustAnchor(agent_admin_name, agent_admin_password);
}
```

### Publishing a credential schema

In order to issue credentials, you need to publish a `CredentialSchema` on the ledger:

```javascript
const name = "My Schema";
const version = "0.0.1";
const attributes = [
	'first_name',
	'last_name'
];

const cred_schema = await agent.createCredentialSchema(name, version, attributes);
```

### Publishing a credential definition

In order to issue credentials, you need to publish a `CredentialDefinition` on the ledger:

```javascript
const cred_def = await agent.createCredentialDefinition(cred_schema.id);
```

### Offering credentials

Create a `Credential` marked for the other agent with the state 'outbound_offer' and wait for it to enter the `issued`
state:

```javascript
const to = {
	did: accepted_connection.remote.pairwise.did
};

const attributes = {
	'first_name': 'John',
	'last_name': 'Doe'
};

const credential_offer = await agent.offerCredential(to, cred_def.id, attributes);
const issued_credential = await agent.waitForCredential(credential_offer.id);
```

### Accepting offered credentials

Find `Credential`s with the state `inbound_offer` and change their state to `accepted`:

```javascript
const opts = {
	state: 'inbound_offer'
};

const credential_offers = await agent.getCredentials(opts);
for (const index in credential_offers) {
	const accepted_credential = await agent.updateCredential(credential_offers[index].id, 'accepted');
}
```

## Verifying

Once you have a `Connection` to another agent, you can send and receive `Verifications` over that connection.

### Publishing a proof schema

You must publish a `ProofSchema` before creating a verification.  `ProofSchema`s describe the information that can be
requested in a `Verification`.

```javascript
const name = 'first_and_last_name';
const version = '0.0.1';
const requested_attributes = {
	first_name_referent: {
		name: 'first_name'
	},
	last_name_referent: {
		name: 'last_name',
		restrictions: [
			{
				cred_def_id: cred_def.id
			}
		]
	}
};

const proof_schema = await agent.createProofSchema(name, version, requested_attributes);
```

### Requesting verification

Create a `Verification` with the state a proof request to a given agent based on a published proof schema:

```javascript
const to = {
	did: accepted_connection.remote.pairwise.did
};

const proof_request = await agent.createVerification(to, proof_schema.id, 'outbound_proof_request');
const finished_verification = await agent.waitForVerification(proof_request.id);
```

### Responding to proof requests

Get a list of `Verification`s with the state `inbound_proof_request` and change their state to `proof_generated` and
then `proof_shared`:

```javascript
const opts = {
	state: 'inbound_proof_request'
};

const inbound_proof_requests = await agent.getVerifications(opts);

for (const index in inbound_proof_requests) {
	const verification = inbound_proof_requests[index];
	await agent.updateVerification(verification.id, 'proof_generated');
	await agent.updateVerification(verification.id, 'proof_shared');
}
```

### Checking the values in a proof

Check the revealed attributes in a `Verification` that has reached the `passed` state.

```javascript
for (const index in finished_verification.info.attributes) {
    const attr = finished_verification.info.attributes[index];
    
    console.log(`${attr.cred_def_id ? '*' : ' '}${attr.name} = ${attr.value}`);
    
    if (attr.name = 'first_name') {
    	assert(attr.value === 'John');
    } else if (attr.name = 'last_name') {
    	assert(attr.cred_def_id && attr.value === 'Doe')
    }
}
```

## More information

The SDK code has fairly extensive [JSDoc comments](sdk.js).  Read these to get a better understanding of all the
capabilities of this SDK.