const Agent = require('../sdk').Agent;
const dotenv = require('dotenv');
const expect = require('chai').expect;

dotenv.config();

const {
	ACCOUNT_URL: accountUrl,
	ADMIN_ID: adminId,
	ADMIN_NAME: adminName,
	ADMIN_PASSWORD: adminPassword,
	ISSUER_AGENT_NAME: issuerName,
	HOLDER_AGENT_NAME: holderName,
	VERIFIER_AGENT_NAME: verifierName,
	LOG_LEVEL: logLevel,
	PURGE: purge
} = process.env;

let holder;
let holderIdentity;
let issuer;
let issuerIdentity;
let verifier;
let verifierIdentity;
let ignoreConnectionError = false;

describe('sdk', () => {

	let credential;
	let credentialDefinition; // the credential definition (published to ledger)
	let pairwiseDid; // the private pairwise DID of a connection
	let proofSchema;
	let schema; // the schema (published to ledger)
	let verification;

	before(async () => {
		const admin = new Agent(accountUrl, adminId, adminName, adminPassword, adminName, logLevel);
		const adminIdentity = await admin.getIdentity();
		expect(adminIdentity).to.not.be.undefined;

		// make sure the specified agents live in this account already.  Create
		//  agent objects for each
		const targets = [holderName, issuerName, verifierName];
		let agents = await admin.request('agents');
		if (agents && agents.count > 0 && agents.items && agents.items.length > 0) {
			for (const agent of agents.items) {
				const targetIndex = targets.indexOf(agent.name);
				if (targetIndex < 0) {
					continue;
				}
				switch (agent.name) {
					case holderName:
						holder = new Agent(accountUrl, agent.id, agent.name, agent.pass, agent.name, logLevel);
						break;
					case issuerName:
						issuer = new Agent(accountUrl, agent.id, agent.name, agent.pass, agent.name, logLevel);
						break;
					case verifierName:
						verifier = new Agent(accountUrl, agent.id, agent.name, agent.pass, agent.name, logLevel);
						break;
				}
				targets.splice(targetIndex, 1);
			}
		}

		if (targets.length !== 0) {
			console.log(`Some agents aren't set up, yet: ${targets}`);
			process.exit(1);
		}

		holderIdentity = await holder.getIdentity();
		issuerIdentity = await issuer.getIdentity();
		verifierIdentity = await verifier.getIdentity();

		// THIS WILL DELETE DATA IF SET
		if (purge && typeof purge === "string" && purge.toLowerCase() === "true") {
			ignoreConnectionError = true;
			await removeCredentials(holder, ignoreConnectionError);

			await removeConnections(holder);
			await removeConnections(issuer);
			await removeConnections(verifier);
			await removeInvitations(holder);
			await removeInvitations(issuer);
			await removeInvitations(verifier);
			purgedPrevious = true;
		}
	});

	it(`should get identity for holder '${holderName}'`, async () => checkIdentity(holder, holderIdentity));

	it(`should get identity for issuer '${issuerName}'`, async () => checkIdentity(issuer, issuerIdentity));

	it(`should get identity for verifier '${verifierName}'`, async () => checkIdentity(verifier, verifierIdentity));

	/**
   * tests a holder initiated connection
   */
	it(`should connect '${holderName}' to '${issuerName}'`, async () => {
		pairwiseDid = await connect(holder, holderIdentity, issuer, issuerIdentity);
	});

	it(`'${issuerName}' should be a trust anchor`, async () => {
		if (issuerIdentity.issuer === false) {
			issuerIdentity = await issuer.onboardAsTrustAnchor();
		}

		expect(issuerIdentity.issuer).to.equal(true);
	});

	it('should publish schema', async () => {
		// create a unique schema for testing
		const name = `Person-${Date.now()}`; // https://schema.org/Person
		const version = '0.0.1';
		const attributes = [
			'jobTitle' // https://schema.org/jobTitle
		];

		schema = await issuer.createCredentialSchema(name, version, attributes);

		expect(schema).to.not.be.undefined;
		expect(schema.id).to.not.be.undefined;

		// validate the schema is contained in the issuer's list
		const schemas = await issuer.getCredentialSchemas();
		const needle = schemas.find(haystack => haystack.id === schema.id);

		expect(needle).to.not.be.undefined;
	});

	it('should publish credential definition', async () => {

		credentialDefinition = await issuer.createCredentialDefinition(schema.id);

		expect(credentialDefinition).to.not.be.undefined;
		expect(credentialDefinition.id).to.not.be.undefined;

		// validate the credential definition is contained in the issuer's list
		const definitions = await issuer.getCredentialDefinitions();

		expect(definitions.find(d => d.id === credentialDefinition.id)).to.not.be.undefined;
	});

	/**
   * issuer-initiated credential issuance
   */
	it(`should issue credential from '${issuerName} to '${holderName}'`, async () => {
		credential = await issueCredential(issuer, holder, credentialDefinition, pairwiseDid);
	});

	it(`should get credentials for '${holderName}'`, async () => {
		const credentials = await holder.getCredentials();

		expect(credentials).to.not.be.undefined;
		expect(credentials.length).to.be.greaterThan(0);
		expect(credentials.find(c => c.id === credential.id)).to.not.be.undefined;
	});

	it(`should delete credential for '${holderName}'`, async () => {
		await holder.deleteCredential(credential.id);
		const credentials = await holder.getCredentials();

		expect(credentials.find(c => c.id === credential.id)).to.be.undefined;
	});

	/**
   * holder-initiated credential issuance
   */
	it(`should request credential for '${holderName}' from '${issuerName}'`, async () => {
		// find the connection that applies to the issuer
		const holderConnections = await holder.getConnections();
		const connection = holderConnections.find(c => c.local.pairwise.did === pairwiseDid);

		expect(connection).to.not.be.undefined;

		const to = {did: connection.remote.pairwise.did};

		// make the request from holder to issuer
		const credentialRequest = await holder.requestCredential(to, {schema_name: schema.name, schema_version: schema.version}); // FIXME, why not just use schema.name and schema.version or pass in the actual schema object

		// as a issuer, get the credential request
		const issuerOffers = await issuer.getCredentials({state: 'inbound_request'}); // FIXME getRequests() seems more natural
		const request = issuerOffers.find(r => r.id === credentialRequest.id);

		expect(request).to.not.be.undefined;

		// issue the credential from this request
		credential = await issueCredentialFromRequest(issuer, holder, request.id);
	});

	it(`should disconnect '${holderName}' from '${issuerName}'`, async () => await disconnect(holder, issuer, pairwiseDid));

	it(`should create proof request for '${verifierName}'`, async () => {
		const name = `${schema.name}-${verifierName}`;
		const version = '0.0.1';

		// specify the attributes required in the proof and any restrictions on the credential supplied
		const requestedAttributes = {
			jobTitleReferent: {
				name: 'jobTitle',
				restrictions: [
					{
						cred_def_id: credentialDefinition.id
					}
				]
			}
		};

		proofSchema = await verifier.createProofSchema(name, version, requestedAttributes);
		expect(proofSchema).to.not.be.undefined;
	});

	it(`should connect '${holderName}' to '${verifierName}'`, async () => {
		pairwiseDid = await connect(holder, holderIdentity, verifier, verifierIdentity);
	});

	it(`should request proof from '${holderName}' by '${verifierName}'`, async () => {
		// find the connection to the holder
		const verifierConnections = await verifier.getConnections();
		const connection = verifierConnections.find(c => c.remote.pairwise.did === pairwiseDid);

		expect(connection).to.not.be.undefined;

		// request proof
		const to = {
			did: connection.remote.pairwise.did
		};

		const proofRequest = await verifier.createVerification(to, proofSchema.id, 'outbound_proof_request');
		expect(proofRequest).to.not.be.undefined;
		expect(proofRequest.proof_request).to.not.be.undefined;

		// view proof requests and find the one from the verifier
		const proofRequests = await holder.getVerifications({state: 'inbound_proof_request'});
		expect(proofRequests).to.not.be.undefined;
		verification = proofRequests.find(r => r.proof_request.name === proofRequest.proof_request.name && r.proof_request.version === proofRequest.proof_request.version);
		expect(verification).to.not.be.undefined;

		// provide proof
		await holder.updateVerification(verification.id, 'proof_generated');
		await holder.updateVerification(verification.id, 'proof_shared');

		// validate it passed
		const verifications = await verifier.getVerifications();
		verification = verifications.find(v => v.proof_request.name === proofSchema.name &&
      v.proof_request.version === proofSchema.version);

		expect(verification).to.not.be.undefined;
		expect(verification.state).to.equal('passed');
	});

	it(`should delete verification from '${verifierName}'`, async () => {
		const {id}= verification;

		await verifier.deleteVerification(verification.id);
		const verifications = await verifier.getVerifications();

		expect(verifications.find(v => v.id === id)).to.be.undefined;
	});

	it(`should disconnect '${holderName}' from '${verifierName}'`, async () => await disconnect(holder, verifier, pairwiseDid));

});

/**
 * Validates identity data.
 * @param {Agent} agent The agent that proxies the identity
 * @param {AgentInfo} identity The identity information
 * @return {undefined}
 */
async function checkIdentity (agent, identity) {
	const {user}= agent;
	const {name, url}= identity;

	expect(identity).to.not.be.undefined;
	expect(name).to.equal(user);
	let agent_url;
	if (accountUrl.indexOf('://') > 0) {
		agent_url = `${accountUrl}/api/v1/agents/${agent.id}`;
	} else {
		agent_url = `https://${accountUrl}/api/v1/agents/${agent.id}`;
	}

	expect(url).to.equal(agent_url);
}

/**
 * Connects A to B, where A and B are two agents.
 * @param {Agent} aAgent the A agent
 * @param {AgentInfo} aIdentity the A identity information
 * @param {Agent} bAgent the B agent
 * @param {AgentInfo} bIdentity the B identity information
 * @returns {Promise<string>} A promise that returns the remote pairwise DID of the connection.
 */
async function connect (aAgent, aIdentity, bAgent, bIdentity) {
	const to = {url: bIdentity.url}; // create the connection request body

	// see if connection already exists
	// TODO

	// make the invitation
	const invitation = await bAgent.createInvitation();
	expect(invitation).to.not.be.undefined;
	expect(invitation.url).to.not.be.undefined;

	const properties = {testkey: 'testvalue'};
	const aConnection = await aAgent.acceptInvitation(invitation.url, properties);
	expect(aConnection.state).to.be.equal('outbound_offer');
	expect(aConnection.local).to.not.be.undefined;
	expect(aConnection.local.properties).to.not.be.undefined;
	expect(aConnection.local.properties.testkey).to.be.equal(properties.testkey);

	// verify the connections exist
	const aConnections = await aAgent.getConnections();
	const bConnections = await bAgent.getConnections();

	expect(aConnections.length).to.be.greaterThan(0);
	expect(bConnections.length).to.be.greaterThan(0);
	expect(bConnections.find(c => c.id === aConnection.id)).to.not.be.undefined;
	//TODO expect(aConnection.remote.url).to.equal(bIdentity.url);

	return aConnection.local.pairwise.did;
}

/**
 * Disconnects A from B, where A and B are two agents.
 * @param {Agent} aAgent the A agent
 * @param {Agent} bAgent the B agent
 * @param {string} did Pairwise DID to find the connection
* @returns {Promise<void>} A promise that resolves when the test completes.
 */
async function disconnect (aAgent, bAgent, did) {
	// get the current connections
	let aConnections = await aAgent.getConnections();

	// find the connection that applies to B
	let connection = aConnections.find(c => c.local && c.local.pairwise.did === did);

	if (connection) {
		// delete the connection using A
		await aAgent.deleteConnection(connection.id);

		// verify the connection is deleted
		aConnections = await aAgent.getConnections();
		connection = aConnections.find(c => c.local && c.local.pairwise.did === did);

		expect(connection).to.be.undefined;

		const bConnections = await bAgent.getConnections();
		connection = bConnections.find(c => c.remote.pairwise.did === did);

		expect(connection).to.be.undefined;
	}
}

/**
 * Deletes all connections for an agent.
 * @param {Agent} agent the Agent
 * @returns {Promise<void>} A promise that resolves when all connections are deleted.
 */
async function removeConnections (agent) {
	const connections = await agent.getConnections();

	for (const connection of connections) {
		await agent.deleteConnection(connection.id);
	}
}

/**
 * Deletes all invitations for an agent.
 * @param {Agent} agent the Agent
 * @returns {Promise<void>} A promise that resolves when all invitations are deleted.
 */
async function removeInvitations (agent) {
	const invitations = await agent.getInvitations();

	for (const invitation of invitations) {
		await agent.deleteInvitation(invitation.id);
	}
}

/**
 * Deletes all credentials in an agent's wallet.
 * @param {Agent} agent the Agent
 * @returns {Promise<void>} A promise that resolves when all credentials are deleted.
 */
async function removeCredentials (agent, ignoreConnectionError) {
	const credentials = await agent.getCredentials();

	for (const credential of credentials) {
		try {
			await agent.deleteCredential(credential.id);
		} catch (error) {
			// detect if we are ignoring connection error
			if (ignoreConnectionError && error.message.toLowerCase().indexOf('no connection found') !== -1) {
				continue;
			}
			throw error;
		}
	}
}

/**
 * Issues a credential from issuer to holder.
 * @param {Agent} issuer The issuer's agent
 * @param {Agent} holder The holder's agent
 * @param {CredentialDefinition} credentialDefinition The schema or cred def the credential is based on
 * @param {string} did The DID to find the connection to issue the credential to
 * @returns {Promise<Credential>} A promise that resolves with the credential offer.
 */
async function issueCredential (issuer, holder, credentialDefinition, did) {
	// find the connection that applies to the holder (this was stored earlier from the connection)
	const issuerConnections = await issuer.getConnections();
	const connection = issuerConnections.find(c => c.remote.pairwise.did === did);

	expect(connection).to.not.be.undefined;

	const to = {did: connection.remote.pairwise.did};
	const attributes = {'jobTitle': 'Developer'};

	// make the offer from issuer to holder
	const iOffer = await issuer.offerCredential(to, { schema_name: credentialDefinition.schema.name, schema_version: credentialDefinition.schema.version }, attributes);

	// as a holder, accept the credential offer
	const holderOffers = await holder.getCredentials({state: 'inbound_offer'});
	expect(holderOffers.length).to.be.greaterThan(0);

	// find the offer related to this test suite
	const hOffer = holderOffers.find(offer => offer.id === iOffer.id);
	expect(hOffer).to.not.be.undefined;

	const credential = await holder.updateCredential(hOffer.id, 'accepted');
	expect(credential).to.not.be.undefined;

	return credential;
}

/**
 * Issues a credential from issuer based on a credential request and tests to make sure holder got it.
 * This code assumes that holder is the recipient of the generated credential offer.
 * @param {Agent} issuer The issuer's agent
 * @param {Agent} holder The holder's agent
 * @param {string} requestId The id of the issuer's inbound credential request
 * @returns {Promise<Credential>} A promise that resolves with the credential offer.
 */
async function issueCredentialFromRequest (issuer, holder, requestId) {
	// as a issuer, get the credential request
	const issuerOffers = await issuer.getCredentials({state: 'inbound_request'});
	const request = issuerOffers.find(r => r.id === requestId);

	expect(request).to.not.be.undefined;


	const attributes = {'jobTitle': 'Developer'};
	const iOffer = await issuer.updateCredential(requestId, 'outbound_offer', attributes);

	// as a holder, accept the credential offer
	const holderOffers = await holder.getCredentials({state: 'inbound_offer'});
	expect(holderOffers.length).to.be.greaterThan(0);

	// find the offer related to this test suite
	const hOffer = holderOffers.find(offer => offer.id === iOffer.id);
	expect(hOffer).to.not.be.undefined;

	const credential = await holder.updateCredential(hOffer.id, 'accepted');
	expect(credential).to.not.be.undefined;

	return credential;
}
