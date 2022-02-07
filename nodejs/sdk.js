/**
 © Copyright IBM Corp. 2019, 2019

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

const async = require('async');
// node-fetch in v3+ needs to be imported from a module.  This is the way to load
//  it into CommonJS per npmjs.com documentation for node-fetch
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const URL = require('url').URL;
const https = require('https');
const http = require('http');

const jsonPrint = function (o) {
	if (typeof o === 'string') return o;
	return JSON.stringify(o, 2, ' ');
};

const LOG_LEVELS = Object.freeze([
	'trace',
	'debug',
	'info',
	'warn',
	'error',
	'fatal',
	'disabled'
]);

/**
 * A simple logging mechanism for the SDK.
 */
class Logger {

	/**
	 * Creates a Logger with the given logging level that will prefix messages with the given name.
	 * @param {'trace'|'debug'|'info'|'warn'|'error'|'fatal'} log_level The desired logging level.
	 * @param {string} name The prefix for the log messages.
	 */
	constructor (log_level, name) {
		if (!name || typeof name !== 'string')
			throw new TypeError(`Invalid logger name: ${name}`);
		if (LOG_LEVELS.indexOf(log_level) < 0)
			throw new TypeError(`Invalid log level: ${log_level}`);
		this.name = name;
		this.level = log_level;
	}

	setLogLevel (level) {
		if (LOG_LEVELS.indexOf(level) < 0)
			throw new Error(`Invalid log level: ${level}`);

		this.level = level;
	}

	trace (message) {
		const valid_levels = LOG_LEVELS.slice(LOG_LEVELS.indexOf(this.level), LOG_LEVELS.length);
		if (valid_levels.indexOf('trace') >= 0)
			console.log(make_message(message, 'trace', this.name));
	}

	debug (message) {
		const valid_levels = LOG_LEVELS.slice(LOG_LEVELS.indexOf(this.level), LOG_LEVELS.length);
		if (valid_levels.indexOf('debug') >= 0)
			console.log(make_message(message, 'debug', this.name));
	}

	info (message) {
		const valid_levels = LOG_LEVELS.slice(LOG_LEVELS.indexOf(this.level), LOG_LEVELS.length);
		if (valid_levels.indexOf('info') >= 0)
			console.log(make_message(message, 'info', this.name));
	}

	warn (message) {
		const valid_levels = LOG_LEVELS.slice(LOG_LEVELS.indexOf(this.level), LOG_LEVELS.length);
		if (valid_levels.indexOf('warn') >= 0)
			console.log(make_message(message, 'warn', this.name));
	}

	error (message) {
		const valid_levels = LOG_LEVELS.slice(LOG_LEVELS.indexOf(this.level), LOG_LEVELS.length);
		if (valid_levels.indexOf('error') >= 0)
			console.log(make_message(message, 'error', this.name));
	}

	fatal (message) {
		const valid_levels = LOG_LEVELS.slice(LOG_LEVELS.indexOf(this.level), LOG_LEVELS.length);
		if (valid_levels.indexOf('fatal') >= 0)
			console.log(make_message(message, 'fatal', this.name));
	}
}

function make_message (message, level, name) {
	return `${new Date().toISOString()} [${name}] ${level}: ${message}`;
}

class Agent {

	/**
	 * Constructs an Agent instance for a user
	 *
	 * @param {string} account_url  The Agent endpoint url
	 * @param {string} agent_id  Id for Agent endpoint
	 * @param {string} agent_name  User name for Agent endpoint
	 * @param {string} agent_password Password for Agent endpoint
	 * @param {string} friendly_name The human readable name of the user
	 * @param {string} log_level Logging level for Agent debugging
	 */
	constructor (account_url, agent_id, agent_name, agent_password, friendly_name, log_level) {
		this.setUrl(account_url);
		this.setUserPassword(agent_id, agent_password);
		this.setUserName(friendly_name);
		this.user = agent_name;
		this.logger = new Logger(log_level || 'disabled', `agent/${this.user}`);
	}

	/**
	 * Set url of Agent
	 *
	 * @param {string} url The new URL for the Agency.
	 * @returns {void}
	 */
	setUrl (url) {
		this.url = url;
	}

	/**
	 * Set user and password for user's Agent
	 *
	 * @param {string} id A TI Agent identity.
	 * @param {string} pw The password for the Agency identity.
	 * @returns {void}
	 */
	setUserPassword (id, pw) {
		this.id = id;
		this.pw = pw;
		this.authHeader = 'Basic ' + Buffer.from(id + ':' + pw).toString('base64');
	}

	/**
	 * Set user name that is displayed in the agent UI
	 *
	 * @param {string} user The name of the user
	 * @returns {void}
	 */
	setUser (user) {
		this.user = user;
	}

	/**
	 * Set human readable user name that is displayed in connection, credential or proof UI
	 *
	 * @param {string} name The human readable name of the user
	 * @returns {void}
	 */
	setUserName (name) {
		this.name = name;
	}

	/**
	 * Enable logging for the agent by setting a logging level.
	 *
	 * @param {'trace'|'debug'|'info'|'warn'|'error'|'fatal'} log_level The desired logging level.
	 * @returns {void}
	 */
	setLoggingLevel (log_level) {
		this.logger.setLogLevel(log_level);
	}


	//---------------------------------------------------------------------------------
	// IDENTITIES
	//---------------------------------------------------------------------------------

	/**
	 * A URL associated with a cloud agent account.
	 * @typedef {string} AccountURL
	 */

	/**
	 * The name of an agent.  Generally only useful if you also know the {@link AccountURL}.  Ex. admin, gov-dmv, thrift, etc.
	 * @typedef {string} AgentName
	 */

	/**
	 * The URL needed to connect to an agent.  Combines the {@link AgentName} and {@link AccountURL}.
	 * @typedef {string} AgentURL
	 */

	/**
	 * Represents an agent on a given cloud agent account.
	 * @typedef {object} AgentInfo
	 * @property {string} id The id of the agent.
	 * @property {AgentName} name The name of the agent.
	 * @property {AgentURL} url The url for the agent.
	 * @property {AgentURL} connection_url The url that represents the agent in a connection object.
	 * @property {Verkey} verkey The public key for the agent.
	 * @property {string} creation_time A datetime string for when the agent was created.
	 * @property {DID} did The DID for the agent.
	 * @property {boolean} issuer Whether the agent is an ENDORSER on the default ledger.  ENDORSERs are allowed to publish credential schemas and
	 * definitions.
	 */

	/**
	 * Get this agent's {@link AgentInfo}.
	 *
	 * @return {Promise<AgentInfo>} A promise that resolves with information about the agent.
	 */
	async getIdentity () {

		this.logger.info(`Getting agent info for ${this.user}`);
		const r = await this.request('info');
		this.logger.debug('User = '+jsonPrint(r));
		return r;
	}

	/**
	 * Create a {@link AgentInfo} on the account.  If self_registration is disabled, you have to create an agent with
	 * some password, and then change that password as the agent that was created.  This function attempts to handle
	 * both self-registration and non-self-registration scenarios.
	 *
	 * @param {string} account_admin_agent_id The admin agent on this agent's account. Only needed if create is true.
	 * @param {string} account_admin_agent_password The admin agent's password.
	 * @return {Promise<AgentInfo>} A promise that resolves with information about the agent that was created.
	 */
	async createIdentity (account_admin_agent_id, account_admin_agent_password) {
		if (!account_admin_agent_id || typeof account_admin_agent_id !== 'string')
			throw new TypeError('Account\'s admin agent name was not provided');
		if (!account_admin_agent_password || typeof account_admin_agent_password !== 'string')
			throw new TypeError('Invalid admin agent password');

		const admin_auth = 'Basic ' + Buffer.from(account_admin_agent_id + ':' + account_admin_agent_password).toString('base64');

		this.logger.info(`Creating agent: ${this.user}`);
		try {
			const r = await this.request('agents', {
				'headers': {'Authorization': admin_auth},
				'method': 'POST',
				'body': JSON.stringify({'name': this.user, 'password': this.pw})
			});
			this.logger.debug('Result from creating identity: '+jsonPrint(r));
			// id is auto-generated
			this.id = r.id;
			// correct the auth header to account for the new id value
			this.setUserPassword(this.id, this.pw);
			return r;
		} catch (error) {
			this.logger.error(`Failed to create identity: ${error}`);
			throw error;
		}
	}

	/**
	 * Delete agent.
	 *
	 * @param {boolean} force To delete an account agent with child agents, force will need to be true.
	 * @return {Promise<void>} A promise that resolves when the agent is deleted.
	 */
	async deleteIdentity (force) {
		let query = '';
		if (force && force === true) {
			query = '?force';
		}
		this.logger.info(`Deleting agent info for ${this.user}`);
		await this.request(`agents/${this.id}${query}`, {
			'method': 'DELETE'
		});
		this.logger.debug(`Successfully deleted user ${this.user}`);
	}

	/**
	 * Set this agent's role to TRUST_ANCHOR on the ledger, giving the agent the ability to publish schemas and
	 * credential definitions, which are needed to issue credentials.  The request to make an agent a
	 * TRUST_ANCHOR may be made with account admin credentials and a seed, or without parameters.
	 *
	 * @param {string} account_admin_agent_id The admin agent id on this agent's account. Only needed if create is true.
	 * @param {string} account_admin_agent_password The admin agent's password.
	 * @param {string} [seed] A valid trustee seed.  Allows this agent to generate the NYM transaction as the network's trustee.
	 * @returns {Promise<AgentInfo>} A promise that resolves with the updated agent information.
	 */
	async onboardAsTrustAnchor (account_admin_agent_id, account_admin_agent_password, seed) {
		if (seed && typeof seed !== 'string')
			throw new TypeError('Invalid seed for onboarding as a Trust Anchor');

		const body = {
			role: {name: 'ENDORSER'}
		};

		this.logger.info(`Registering ${this.user} as a Trust Anchor`);
		let r1 = null;
		if (account_admin_agent_id && account_admin_agent_password) {
			if (seed) body.seed = seed;
			const auth = 'Basic ' + Buffer.from(account_admin_agent_id + ':' + account_admin_agent_password).toString('base64');
			r1 = await this.request('agents/' + this.id, {
				'headers': {'Authorization': auth},
				'method': 'PATCH',
				'body': JSON.stringify(body)
			});
		} else {
			r1 = await this.request('agents/' + this.id, {
				'method': 'PATCH',
				'body': JSON.stringify(body)
			});
		}
		this.logger.info(`Registered ${this.user} as a Trust Anchor`);
		this.logger.debug('Result from onboardAsTrustAnchor: '+jsonPrint(r1));
		return r1;
	}


	/**
	 * Get all listeners
	 *
	 * @returns {object[]} Array of listener objects
	 */
	async getListeners () {
		const r = await this.request('listeners');
		this.logger.debug('Result from getListeners: '+jsonPrint(r));
		return r;
	}

	/**
	 * Delete listener
	 *
	 * @param {string} id The ID of a listener
	 * @returns {object} The delete response from Agency
	 */
	async deleteListener (id) {
		const r = await this.request('listeners/' + id, {
			'method': 'DELETE'
		});
		this.logger.debug('Result from deleteListener: '+jsonPrint(r));
		return r;
	}

	/**
	 * Get all devices
	 *
	 * @returns {object[]} Array of device objects
	 */
	async getDevices () {
		const r = await this.request('devices');
		this.logger.debug('Result from getDevices: '+jsonPrint(r));
		return r;
	}

	/**
	 * Delete device
	 *
	 * @param {string} id The ID of a device
	 * @returns {object} The delete response from Agency
	 */
	async deleteDevice (id) {
		const r = await this.request('devices/' + id, {
			'method': 'DELETE'
		});
		this.logger.debug('Result from deleteDevice: '+jsonPrint(r));
		return r;
	}


	//*********************************************************************************
	// CREDENTIAL SCHEMAS
	//*********************************************************************************

	/**
	 * The identifier for a {@link CredentialSchema} on both the agent and the public ledger.  If you're curious, the
	 * ID is composed of the schema publisher's {@link DID}, a transaction type, the schema name, and the schema version.
	 * Ex. "R4PbDKCjZTWFh1vBc5Zaxc:2:Thrift Account:1.0"
	 * @typedef {string} CredentialSchemaID
	 */

	/**
	 * A CredentialSchema represents a list of attributes that a credential based on the schema can contain.
	 * {
	 *   "attr_names": [
	 *     "first_name",
	 *     "last_name"
	 *   ],
	 *   "id": "R4PbDKCjZTWFh1vBc5Zaxc:2:Thrift Account:1.0",
	 *   "name": "Thrift Account",
	 *   "namever": "Thrift Account:1.0",
	 *   "version": "1.0"
	 * }
	 * @typedef {object} CredentialSchema
	 * @property {CredentialSchemaID} id The ID of the schema.
	 * @property {string} name The name of the schema.
	 * @property {string} version A tuple representing the schema version (1.0, 1.1.2, etc.).
	 * @property {string} namever The name and version joined with a ':'.
	 * @property {string[]} attr_names The list of attributes that a credential based on the schema can have.
	 */

	/**
	 * Creates a {@link CredentialSchema}, meaning the schema is published on the ledger.
	 *
	 * @param {string} name The name of the schema.
	 * @param {string} version A tuple representing the schema version (1.0, 1.1.2, etc.)
	 * @param {string[]} attributes The list of attributes credentials based on this schema must have.
	 * @return {Promise<CredentialSchema>} A promise that resolves with the new schema record.
	 */
	async createCredentialSchema (name, version, attributes) {
		if (!name || typeof name !== 'string')
			throw new Error('Cannot create a credential schema without a name');
		if (!version || typeof version !== 'string')
			throw new Error('Cannot create a credential schema without a version');
		if (!attributes.length || typeof attributes[0] !== 'string')
			throw new Error('Cannot create a credential schema without attributes');

		this.logger.info(`Creating credential schema ${name} ${version}`);
		this.logger.debug(`Credential schema ${name} ${version} attributes: ${jsonPrint(attributes)}`);
		const r = await this.request('credential_schemas', {
			'method': 'POST',
			'body': JSON.stringify({'name':name, 'version':version, 'attrs':attributes})
		});
		this.logger.info(`Published credential schema ${r.id}`);
		this.logger.debug('Result from createCredentialSchema: '+jsonPrint(r));
		return r;
	}

	/**
	 * Get a {@link CredentialSchema} record.
	 *
	 * @param {CredentialSchemaID} id The ID of the schema
	 * @return {Promise<CredentialSchema>} A promise that resolves with the schema object, or null if not found
	 */
	async getCredentialSchema (id) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Must provide an ID to lookup a credential schema');

		this.logger.info(`Getting credential schema ${id}`);
		const r = await this.request(`credential_schemas/${id}`);
		this.logger.info(`Got credential schema ${r.id}`);
		this.logger.debug('Result from getCredentialSchema: '+jsonPrint(r));
		return r;
	}

	/**
	 * An object listing [BSON query parameters]{@link https://docs.mongodb.com/manual/reference/operator/query/} that
	 * correspond to the fields in a {@link CredentialSchema}.  The fields below are just examples to give you an idea;
	 * there are other queries you can make.
	 * {
	 *     name: 'My Schema',
	 *     version: { $neq: '1.0' }
	 * }
	 * @typedef {object} CredentialSchemaQueryParams
	 * @property {string} [id] The ID of the schema
	 * @property {string} [name] The name of the schema
	 */

	/**
	 * A set of parameters that cause the agent to collect a set of responses from other agents that it has connections
	 * to.  It's a list of {@link Connection} property names and values. For example,
	 * {
	 *     property1: true,
	 *     property2: 'prop2'
	 * }
	 * causes this agent to look for connections with property1=true.  It will send propagate the request to each
	 * relevant connection.  The agents receiving the request will look for connections with property2=prop2 custom and
	 * recursively propagate the request along those connections, etc.
	 * @typedef {object} QueryRoute
	 * @property {boolean} [trustedVerifier] Propagates the request to connections with trusted verifiers.
	 * @property {boolean} [trustedIssuer] Propagates the request to connections with trusted issuers.
	 */

	/**
	 * @typedef {object} AgentResponse
	 * @property {DID} did The pairwise DID for the remote agent.
	 * @property {AgentName} name The agent name for the remote agent.
	 * @property {object} results The list of {@link CredentialSchemas} or {@link CredentialDefinitions} found by the
	 * remote agent.
	 * @property {number} results.count The number of results found by the remote agent.
	 * @property {CredentialSchema[]|CredentialDefinition[]}
	 */

	/**
	 * @typedef {object} RouteResponse
	 * @property {AgentResponse[]} agents A list of agent responses containing
	 */

	/**
	 * Get a list of all {@link CredentialSchema}s published by your agent, if no parameters are specified, or a list of
	 * credential schemas matching the search parameters.  You can use the `route` parameter to direct the request to
	 * other agents.
	 *
	 * @param {boolean} [all] Indicates whether query should include other agents who have registered their credential schemas.
	 * @param {CredentialSchemaQueryParams} [opts] An optional filter for the schemas that are returned.
	 * @return {Promise<CredentialSchema[]>} A promise that resolves with a list of credential schemas.
	 */
	async getCredentialSchemas (all, opts) {
		let query = '';
		if (all) {
			if (typeof all !== 'boolean')
				throw new TypeError('Invalid "all" parameters');

			query = '?all=true';
		}

		if (opts) {
			if (typeof opts !== 'object')
				throw new TypeError('Invalid query parameters');
			query = `${query}${(query.length === 0 ? '?' : '&')}filter=${JSON.stringify(opts)}`;
		}

		this.logger.info('Getting credential schemas');
		this.logger.debug(`Getting credential schemas that match: ${query}`);
		let r = await this.request(`credential_schemas${query}`);
		if (r.items) r = r.items;
		this.logger.info(`Got ${r.length} credential schemas`);
		this.logger.debug('Result from getCredentialSchemas: '+jsonPrint(r));
		return r;
	}

	//*********************************************************************************
	// CREDENTIAL DEFINITIONS
	//*********************************************************************************

	/**
	 * Resolves to a published credential definition on the ledger.  Consists of a DID, a transaction type (3 means a
	 * credential definition in Hyperledger Indy), CL, a transaction number, and a tag.
	 * Ex. 'JeU3p99QCt3p5tjZJyPwUK:3:CL:357:TAG1'
	 * @typedef {string} CredentialDefinitionID
	 */

	/**
	 * When an issuer wants to issue credentials based on a certain schema, they have to publish a credential definition
	 * on the ledger for that schema.
	 * @typedef {object} CredentialDefinition
	 * @property {object} data The cryptographic content of the credential definition. Good at filling up logs.
	 * @property {CredentialDefinitionID} id The ID of the credential definition on both the agent and the ledger.
	 * @property {CredentialSchemaID} schema_id The credential schema this credential definition pertains to.
	 * @property {string} schema_name The name of the credential schema.
	 * @property {string} version The version of the credential schema.
	 */

	/**
	 * Create a {@link CredentialDefinition}
	 * @param {CredentialSchemaID} schemaId The ledger ID for the schema.
	 * @return {Promise<CredentialDefinition>} The created credential definition.
	 */
	async createCredentialDefinition (schemaId) {
		if (!schemaId || typeof schemaId !== 'string')
			throw new TypeError('Must provide a credential schema ID to create a credential definition');

		this.logger.info(`Creating credential definition for schema ${schemaId}`);
		const r = await this.request('credential_definitions', {
			'method': 'POST',
			'body': JSON.stringify({'schema_id':schemaId})
		});
		this.logger.info(`Created credential definition for schema ${schemaId}`);
		this.logger.debug('Result from createCredentialDefinition: '+jsonPrint(r));
		return r;
	}

	/**
	 * Get a {@link CredentialDefinition}.
	 * @param {CredentialDefinitionID} id The credential definition ID.
	 * @returns {Promise<CredentialDefinition>} A promise that resolves with the credential definition.
	 */
	async getCredentialDefinition (id) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Invalid credential definition ID');

		this.logger.info(`Getting credential definition ${id}`);
		const r = await this.request(`credential_definitions/${id}`);
		this.logger.info(`Got credential definition ${r.id}`);
		this.logger.debug(`Result from getCredentialDefinition: ${jsonPrint(r)}`);
		return r;
	}

	/**
	 * An object listing [BSON query parameters]{@link https://docs.mongodb.com/manual/reference/operator/query/} that
	 * correspond to the fields in a {@link CredentialDefinition}.  The fields below are just examples to give you an idea;
	 * there are other queries you can make.
	 * {
	 *     schema.name: 'My Schema',
	 *     schema.version: { $neq: '1.0' },
	 *     owner_did: 'A4DXofjbeC97WZAHU5MVGK'
	 * }
	 * @typedef {object} CredentialDefinitionQueryParams
	 * @property {string} [id] The ID of the credential definition
	 * @property {string} [schema.name] The name of the schema for the credential definition
	 * @property {string} [schema.version] The version of the schema for the credential definition
	 * @property {string} [owner_did] The public DID of the agent who published the credential definition
	 */

	/**
	 * Get a list of {@link CredentialDefinition}s matching the given parameters, or all of them, if no parameters are
	 * given.
	 *
	 * @param {boolean} [all] Indicates whether query should include other agents who have registered their credential definitions.
	 * @param {CredentialDefinitionQueryParams} [opts] Credential definition search parameters.
	 * @return {Promise<CredentialDefinition[]>} A promise that resolves with a list of credential definitions.
	 */
	async getCredentialDefinitions (all, opts) {
		let query = '';
		if (all) {
			if (typeof all !== 'boolean')
				throw new TypeError('Invalid "all" parameters');

			query = '?all=true';
		}

		if (opts) {
			if (typeof opts !== 'object')
				throw new TypeError('Invalid query parameters');
			query = `${query}${(query.length === 0 ? '?' : '&')}filter=${JSON.stringify(opts)}`;
		}

		this.logger.info('Getting credential definitions');
		this.logger.debug(`Getting credential definitions that match: ${query}`);
		let r = await this.request(`credential_definitions${query}`);
		if (r.items) r = r.items;
		this.logger.info(`Got ${r.length} credential definitions`);
		this.logger.debug('Result from getCredentialDefinitions: '+jsonPrint(r));
		return r;
	}

	//*********************************************************************************
	// PROOF SCHEMAS
	//*********************************************************************************

	/**
	 * Criteria which must be true pertaining to an attribute or predicate in a {@link ProofSchema}.  There is a logical
	 * AND between keys inside a Restriction and a logical OR between the Restrictions in a list. For example, consider
	 * the following restrictions field:
	 *
	 * 'restrictions': [{'schema_name': 'myschema', 'schema_version': '1.0'}, {'cred_def_id': 'XXX'}]
	 *
	 * This can be read as (schema_name == 'myschema' AND schema_version == '1.0') OR cred_def_id == 'XXX'.  The list of
	 * possible restrictions:
	 *
	 * @typedef {object} Restriction
	 * @property {CredentialSchemaID} [schema_id] The DID of a credential schema.
	 * @property {DID} [schema_issuer_did] The DID of the schema issuer.
	 * @property {string} [schema_name] The name of the schema.
	 * @property {string} [schema_version] The value of the schema.
	 * @property {DID} [issuer_did] The DID of the issuer of the credential.
	 * @property {CredentialDefinitionID} [cred_def_id] The credential definition ID.
	 */

	/**
	 * A requirement in a {@link ProofSchema} that asks a prover not to provide a value for something, but to prove
	 * something _about_ a value, such as a value being greater than some limit.  You could, for example, ask someone to
	 * prove that they're older than 21 with the following predicate:
	 * {
	 *   name: 'age',
	 *   p_type: '>',
	 *   p_value: 21,
	 *  restrictions: [{'cred_def_id': '<credential_definition_id>'}]
	 * }
	 * @typedef {object} ProofSchemaPredicate
	 * @property {string} name The name of the attribute.
	 * @property {string} p_type The type of the predicate.  Defines an operation like ">" to check the attribute value.
	 * @property {number} p_value The value of the predicate.  Define the boundary for the operation.
	 * @property {Restriction[]} restrictions A list of {@link Restriction}s to limit what credentials can supply the
	 * attribute for the predicate.
	 */

	/**
	 * Describes a request attribute in a proof request.  If you don't specify any restrictions on the attribute, then
	 * the attribute is 'self attested', meaning the prover can put whatever they want in for that field.
	 * @typedef {object} ProofSchemaAttribute
	 * @property {Restriction[]} [restrictions] A list of {@link Restriction}s on to limit what credentials can supply
	 * the attribute.
	 */

	/**
	 * An object describing the contents of a proof request, which is basically a prepared query for a list of verified
	 * or self attested attributes and predicates from a prover. An example:
	 * {
	 *   'name': 'proof-schema1',
	 *   'version': '1.0',
	 *   'requested_attributes': {
	 *     'attr1_referent': {
	 *       'name': 'attr1',
	 *       'restrictions': [{'schema_name': 'cred_schema1', 'schema_version': '1.0'}]
     *     },
	 *     'attr2_referent': {
	 *       'name': 'attr2',
	 *       'restrictions': [{'cred_def_id': '<credential_definition_id>'}]
	 *     },
	 *     'self_attested_attr1_referent': {
	 *       'name': 'self-attested-attr1'
	 *     },
	 *   },
	 *   'requested_predicates': {
	 *     'predicate1_referent': {
	 *       'name': 'attr3',
	 *       'p_type': '>',
	 *       'p_value': 5,
	 *       'restrictions': [{'cred_def_id': '<credential_definition_id>'}]
	 *     }
	 *   }
	 * }
	 * @typedef {object} ProofSchema
	 * @property {string} id The ID of the proof schema.
	 * @property {string} name The name of the proof schema. Ex. "proof_of_employment".
	 * @property {string} version The version of the proof schema. Ex. "1.0", "1.0.0", etc.
	 * @property {object<ProofSchemaAttribute>} requested_attributes A list of attributes to be provided by credentials
	 * @property {object<ProofSchemaPredicate>} requested_predicates A list of predicates to be included in the proof
	 */

	/**
	 * Create a {@link ProofSchema}.
	 * @param {string} name The name of the schema.
	 * @param {string} version The version of the schema.
	 * @param {object<ProofSchemaAttribute>} [requestedAttributes] A list of requested attributes.
	 * @param {object<ProofSchemaPredicate>} [requestedPredicates] A list of requested predicates.
	 * @returns {Promise<ProofSchema>} A promise that resolves with the created proof schema.
	 */
	async createProofSchema (name, version, requestedAttributes, requestedPredicates) {
		if (!name || typeof name !== 'string')
			throw new TypeError('Invalid name for proof schema');
		if (!version || typeof version !== 'string')
			throw new TypeError('Invalid version for proof schema');
		if (requestedAttributes && typeof requestedAttributes !== 'object')
			throw new TypeError('Invalid requested attributes list for proof schema');
		if (requestedPredicates && typeof requestedPredicates !== 'object')
			throw new TypeError('Invalid requested predicates list for proof schema');

		const body = {
			name: name,
			version: version,
			requested_attributes: requestedAttributes ? requestedAttributes : {},
			requested_predicates: requestedPredicates ? requestedPredicates : {}
		};

		this.logger.info(`Creating proof schema ${name} ${version}`);
		this.logger.debug(`Attributes: ${jsonPrint(requestedAttributes)}\nPredicates: ${jsonPrint(requestedPredicates)}`);
		const r = await this.request('proof_schemas', {
			'method': 'POST',
			'body': JSON.stringify(body)
		});
		this.logger.info(`Created proof schema ${r.id}`);
		this.logger.debug('Result from verifierCreateProofSchema: '+jsonPrint(r));
		return r;
	}

	/**
	 * An object listing [BSON query parameters]{@link https://docs.mongodb.com/manual/reference/operator/query/} that
	 * correspond to the fields in a {@link ProofSchema}.  The fields below are just examples to give you an idea;
	 * there are other queries you can make.
	 * {
	 *     name: 'My Schema',
	 *     version: { $neq: '1.0' }
	 * }
	 * @typedef {object} ProofSchemaQueryParams
	 * @property {string} [name] The name of the proof schema
	 * @property {string} [version] The version of the proof schema
	 */

	/**
	 * Gets a list of {@link ProofSchema}s matching the query parameters, if any are given, or all proof schemas on the agent.
	 * @param {ProofSchemaQueryParams} [opts] Query parameters.
	 * @returns {Promise<ProofSchema[]>} A promise that resolves with a list of proof schemas
	 */
	async verifierGetProofSchemas (opts) {
		let query = '';
		if (opts) {
			if (typeof opts !== 'object')
				throw new TypeError('Invalid query parameters');
			query = `?filter=${JSON.stringify(opts)}`;
		}

		this.logger.info('Getting proof schemas');
		this.logger.info(`Getting proof schemas that match: ${query}`);
		let r = await this.request(`proof_schemas${query}`);
		if (r.items) r = r.items;
		this.logger.info(`Got ${r.length} proof schemas`);
		this.logger.debug('Result from getProofSchemas: '+jsonPrint(r));
		return r;
	}

	/**
	 * Get a {@link ProofSchema}
	 *
	 * @param {string} id The proof schema ID.
	 * @return {Promise<ProofSchema>} A promise that resolves with the proof schema object.
	 */
	async verifierGetProofSchema (id) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Must provide an ID to get a proof schema');

		this.logger.info(`Getting proof schema ${id}`);
		const r = await this.request(`proof_schemas/${id}`);
		this.logger.info(`Got proof schema ${id}`);
		this.logger.debug('Result from verifierGetProofSchema: '+jsonPrint(r));
		return r;
	}

	//*********************************************************************************
	// INVITATIONS
	//*********************************************************************************

	/**
	 * Invitations represent a way for one agent to exchange its endpoint information with another agent.
	 *
	 * @typedef {object} Invitation
	 * @property {string} id A unique identifier for this invitation
     * @property {string} url Invitation url representing the invitation.
     * @property {string} short_url Shortened version of the invitation url.  Good for embedding in QR codes.
     * @property {boolean} direct_route Whether the connection offer resulting from this invitation will be sent directly to the recipient agent.
     * @property {boolean} manual_accept Whether this invitation requires invitee to manually accept the invitation.
     * @property {number} max_acceptances The maximum number of acceptances allowed for this invitation.
     * @property {number} cur_acceptances How many times the invitation has been accepted so far.
     * @property {TimeStamps} timestamps? Timestamps associated with states of the invitation
     * @property {object} properties? Properties of the invitation
     * @property {string} recipient_key A key created by the recipient
	 */

	/**
	 * Gets a {@link Invitation}.
	 * @param {string} id The ID for a invitation.
	 * @return {Promise<Invitation>} A promise that resolves with the given invitation, or rejects if something went wrong.
	 */
	async getInvitation (id) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Invitation ID must be a string');

		this.logger.info(`Getting invitation ${id}`);
		try {
			const r = await this.request(`invitations/${id}`);
			this.logger.info(`Got invitation ${r.id}`);
			this.logger.debug('Result from getInvitation: '+jsonPrint(r));
			return r;
		} catch (error) {
			this.logger.info(`Error getting invitation ${id}, error: ${error}`);
			throw error;
		}
	}

	/**
	 * Delete a {@link Invitation}.
	 *
	 * @param {string} id The ID of an existing invitation.
	 * @returns {Promise<void>} A promise that resolves when the invitation is deleted.
	 */
	async deleteInvitation (id) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Invitation ID was not provided');

		this.logger.info(`Deleting invitation ${id}`);
		const r = await this.request('invitations/' + id, {
			method: 'DELETE'
		});
		this.logger.info(`Deleted invitation ${id}`);
		this.logger.debug('Result from deleteInvitation: '+jsonPrint(r));
	}

	/**
	 * An object listing [BSON query parameters]{@link https://docs.mongodb.com/manual/reference/operator/query/} that
	 * correspond to the fields in a {@link Invitation} object. The keys listed below are simply examples to give you
	 * the idea; there are others.
	 * @typedef {object} InvitationQueryParams
	 * @property {number} max_acceptances The max acceptances value of invitation we're searching for.
	 * @property {object} [properties.meta] The properties of the invitation to match against.
	 * {
	 *     max_acceptances: -1,
	 *     properties.meta.nonce: "skjldflkj39993"
	 * }
	 */

	/**
	 * Returns a list of {@link Invitation}s.  If query parameters are provided, only invitations matching those parameters will
	 * be returned.  If none are specified, all of the agent's invitations will be returned.
	 * @param {InvitationQueryParams} [opts] Connections search parameters.
	 * @return {Promise<Invitation[]>} A list of all connections or only those matching the query parameters.
	 */
	async getInvitations (opts) {
		let query = '';
		if (opts) {
			if (typeof opts !== 'object')
				throw new TypeError('Invalid query parameters');
			query = `?filter=${JSON.stringify(opts)}`;
		}

		this.logger.info('Getting invitations');
		let r = await this.request(`invitations${query}`);
		if (r.items) r = r.items;
		this.logger.info(`Got ${r.length} invitations`);
		this.logger.debug(`Result from getInvitations for query '${query}': ${jsonPrint(r)}`);
		return r;
	}

	/**
	 * Create connection invitation.
	 * @param {string} direct_route If true, the resulting connection offer will go directly to this agent.  Default true.
	 * @param {string} manual_accept Whether to allow agent to automatically accept this invitation.  Default false.
	 * @param {number} max_acceptances The maximum number of times this invitation can be accepted.  Default -1 (unlimited)
	 * @param {object} properties The properties to embed in the invitation
	 * @return {Promise<Invitation>} The created {@link Invitation}.
	 */
	async createInvitation (direct_route, manual_accept, max_acceptances, properties) {
		if (typeof direct_route !== "undefined" && typeof direct_route !== 'boolean')
			throw new TypeError('Invalid invitation direct route');
		if (typeof manual_accept !== "undefined" && typeof manual_accept !== 'boolean')
			throw new TypeError('Invalid invitation manual accept');
		if (typeof max_acceptances !== "undefined" && typeof max_acceptances !== 'number')
			throw new TypeError('Invalid invitation max acceptances');
		if (typeof properties !== "undefined" && typeof properties !== 'object')
			throw new TypeError('Invalid invitation properties');

		this.logger.info('Creating invitation');
		const body = {};
		if (properties) {
			body.properties = properties;
		}
		if (typeof direct_route !== "undefined") {
			body.direct_route = direct_route;
		}
		if (typeof manual_accept !== "undefined") {
			body.manual_accept = manual_accept;
		}
		if (max_acceptances !== "undefined") {
			body.max_acceptances = max_acceptances;
		}
		const method = 'POST';
		const route = 'invitations';
		this.logger.debug(`Invitation creation parameters: ${jsonPrint(body)}`);
		const r = await this.request(route, {
			method,
			body: JSON.stringify(body)
		});
		this.logger.info(`Created invitation ${r.id}`);
		this.logger.debug('Result from invitation creation: '+jsonPrint(r));
		return r;
	}

	/**
	 * Accept connection invitation.
	 * @param {string} url Invitation url to accept
	 * @param {Properties} [properties] Optional metadata to add to the connection offer.
	 * @return {Promise<Invitation>} The accepted {@link Invitation}.
	 */
	async acceptInvitation (url, properties) {

		if (!url || typeof url !== 'string')
			throw new TypeError('Invalid inviation url');
		if (properties && typeof properties !== 'object')
			throw new TypeError('Invalid properties for accepting invitation');

		const body = {url, properties: properties ? properties : {}};
		if (!body.properties.type) body.properties.type = 'child';

		// Add an optional friendly name to the request
		if (this.name && !body.properties.name) body.properties.name = this.name;

		// It's useful to timestamp offers so you can sort them by most recent
		if (!body.properties.time) body.properties.time = (new Date()).toISOString();

		const method = 'POST';
		const route = 'connections';
		this.logger.debug(`Invitation acceptance parameters: ${jsonPrint(body)}`);
		const r = await this.request(route, {
			method,
			body: JSON.stringify(body)
		});
		this.logger.info(`Accepted invitation ${r.id}`);
		this.logger.debug('Result from invitation acceptance: '+jsonPrint(r));
		return r;
	}

	//*********************************************************************************
	// CONNECTIONS
	//*********************************************************************************

	/**
	 * A unique identifier use in communication on the Hyperledger Indy ledger.  They represent users, agents, issuers, verifiers, etc.
	 * @typedef {string} DID
	 */

	/**
	 * A publicly shared key associated with a DID.  The DID owner proves ownership of the DID using the private/signing key associated with this verkey.
	 * @typedef {string} Verkey
	 */

	/**
	 * A string representing image data.  Generally used to store icons for decorating {@link Connection}s, {@link Credential}s,
	 * and {@link Verification}s.
	 * Ex. 'data:image/png;base64,iVBOR....'
	 * @typedef {string} ImageData
	 */

	/**
	 * Information about an agent involved in a {@link Connection}.
	 *
	 * @typedef {object} ConnectionAgent
	 * @property {AgentName} name The agent name.
	 * @property {string} role The agent's role on the ledger.  Can be 'TRUST_ANCHOR' or 'NONE'.
	 * @property {AgentURL} url The agent url.
	 * @property {object} pairwise Identifying information dedicated to this specific connection.
	 * @property {DID} pairwise.did The pairwise connection DID.
	 * @property {Verkey} pairwise.verkey The pairwise verkey.
	 * @property {object} public Identifying information that has been published to the ledger.
	 * @property {DID} public.did A public DID.
	 * @property {Verkey} public.verkey A public verkey.
	 */

	/**
	 * Represents the state of a {@link Connection}.
	 * @typedef {'inbound_offer'|'outbound_offer'|'connected'|'rejected'} ConnectionState
	 */

	/**
	 * Connections represent a channel for communication between two agents.
	 *
	 * @typedef {object} Connection
	 * @property {string} id A unique identifier for this connection.
	 * @property {object} properties Properties of the connection.  Generally used to sort or decorate connections.
	 * @property {ImageData} [properties.icon] An icon to display when someone views the connection.
	 * @property {string} [properties.name] A friendly name to display when someone views the connection.
	 * @property {string} role This agent's role in the connection.  Can be 'offerer' or 'offeree'.
	 * @property {ConnectionState} state The state of the connection.
	 * @property {ConnectionAgent} [local] Information about this agent's role in the connection. Only present if this
	 * agent has accepted or initiated the connection.
	 * @property {ConnectionAgent} [remote] Information about the other agent's role in this connection. Only present if
	 * that agent accepted or initiated the connection.
	 */

	/**
	 * Gets a {@link Connection}.
	 * @param {string} id The ID for a connection.
	 * @return {Promise<Connection>} A promise that resolves with the given connection, or rejects if something went wrong.
	 */
	async getConnection (id) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Connection ID must be a string');

		this.logger.info(`Getting connection ${id}`);
		const r = await this.request(`connections/${id}`);
		this.logger.info(`Got connection ${r.id}`);
		this.logger.debug('Result from getConnection: '+jsonPrint(r));
		return r;
	}

	/**
	 * Delete a {@link Connection}.
	 *
	 * @param {string} id The ID of an existing connection.
	 * @returns {Promise<void>} A promise that resolves when the connection is deleted.
	 */
	async deleteConnection (id) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Connection ID was not provided');

		this.logger.info(`Deleting connection ${id}`);
		const r = await this.request('connections/' + id, {
			method: 'DELETE'
		});
		this.logger.info(`Deleted connection ${id}`);
		this.logger.debug('Result from deleteConnection: '+jsonPrint(r));
	}

	/**
	 * An object listing [BSON query parameters]{@link https://docs.mongodb.com/manual/reference/operator/query/} that
	 * correspond to the fields in a {@link Connection} object. The keys listed below are simply examples to give you
	 * the idea; there are others.
	 * @typedef {object} ConnectionQueryParams
	 * @property {ConnectionState} [state] The connection state we're searching for.
	 * @property {AgentName} [remote.name] The name of the remote agent to match against.
	 * @property {DID} [remote.pairwise.did] The remote pairwise DID to match.
	 * {
	 *     state: { $neq: 'inbound_offer' },
	 *     'remote.pairwise.did': 'A4DXofjbeC97WZAHU5MVGK'
	 * }
	 */

	/**
	 * Returns a list of {@link Connection}s.  If query parameters are provided, only connections matching those parameters will
	 * be returned.  If none are specified, all of the agent's connections will be returned.
	 * @param {ConnectionQueryParams} [opts] Connections search parameters.
	 * @return {Promise<Connection[]>} A list of all connections or only those matching the query parameters.
	 */
	async getConnections (opts) {
		let query = '';
		if (opts) {
			if (typeof opts !== 'object')
				throw new TypeError('Invalid query parameters');
			query = `?filter=${JSON.stringify(opts)}`;
		}

		this.logger.info('Getting connections');
		this.logger.debug(`getConnections query: ${query}`);
		let r = await this.request(`connections${query}`);
		if (r.items) r = r.items;
		this.logger.info(`Got ${r.length} connections`);
		this.logger.debug(`Result from getConnections for query '${query}': ${jsonPrint(r)}`);
		return r;
	}

	/**
	 * Describes the recipient of a {@link Connection}.  You must specify either the name of an agent in your agent's
	 * same account, or the full {@link AgentURL} to a remote agent.
	 * @typedef {object} ConnectionRecipient
	 * @property {AgentURL} [url] The full {@link AgentURL} for the other agent.
	 * @property {AgentName} [name] The name of an agent in your account.
	 */

	/**
	 * {@link Connection}s, {@link Credential}s, and {@link Verification}s can all be extended by adding additional
	 * properties during their creation.  For example, setting an icon in the properties of a connection could cause
	 * that connection to be displayed with an icon when a user views it in their agent UI.  The properties listed below
	 * are merely examples to demonstrate what these properties could be used for.
	 * @typedef {object} Properties
	 * @property {ImageData} [properties.icon] An image to display when someone views the connection.
	 * @property {string} [properties.name] A friendly name to display for the issuer when the connection is viewed.
	 * @property {string} [properties.time] A timestamp used to sort the connection in a list.
	 */

	/**
	 * Accept a connection offer.  If a connection id is passed, that connection will be updated from state
	 * `inbound_offer` to `connected` on this agent.  If a connection offer object from another agent is passed, the
	 * connection will be created and set to the `connected` state on this agent.
	 *
	 * @param {string|Connection} connection The ID for an existing connection, or an out-of-band connection offer.
	 * @param {Properties} [properties] Optional metadata to add to the connection offer.
	 * @return {Promise<Connection>} The updated connection information.
	 */
	async acceptConnection (connection, properties) {
		if (!connection)
			throw new TypeError('Connection information was not provided');

		let method, body, route;
		if (typeof connection === 'string') {

			if (properties && typeof properties !== 'object')
				throw new TypeError('Invalid properties for accepting connection');

			this.logger.info(`Accepting existing connection with id ${connection}`);
			method = 'PATCH';
			route = `connections/${connection}`;
			body = {
				state: 'connected',
				properties: { // Additional metadata for the connection, Only the state really matters for acceptance
					type: 'child'
				}
			};
			if (!body.properties.type) body.properties.type = 'child';

			// Add an optional friendly name to the request
			if (this.name && !body.properties.name) body.properties.name = this.name;

			// It's useful to timestamp offers so you can sort them by most recent
			if (!body.properties.time) body.properties.time = (new Date()).toISOString();

		} else if (typeof connection === 'object') {

			if (!connection.local || !connection.local.url)
				throw new TypeError('Out-of-band connection offer had invalid offerer information');

			this.logger.info(`Establishing out-of-band connection with ${connection.local.url}`);
			body = connection;
			route ='connections';
			method = 'POST';

		} else {
			throw new TypeError('Invalid connection information');
		}

		this.logger.debug(`Connection acceptance parameters: ${jsonPrint(body)}`);
		const r = await this.request(route, {
			method: method,
			body: JSON.stringify(body)
		});
		this.logger.info(`Accepted connection offer ${r.id}`);
		this.logger.debug('Result from acceptConnection: '+jsonPrint(r));
		return r;
	}


	/**
	 * Waits for a {@link Connection} to enter the 'connected' or 'rejected'.
	 * @param {string} id The connection ID.
	 * @param {number} [retries] The number of times we should check the status of the connection before giving up.
	 * @param {number} [retry_interval] The number of milliseconds to wait between each connection status check.
	 * @return {Promise<Connection>} The accepted {@link Connection}.
	 */
	async waitForConnection (id, retries, retry_interval) {

		let attempts = 0;
		const retry_opts = {
			times: retries ? retries : 30,
			interval: retry_interval ? retry_interval : 3000,
			errorFilter: (error) => {
				// We should stop if the error was something besides still waiting for the connection.
				return error.toString().toLowerCase().indexOf('waiting') >= 0;
			}
		};

		return new Promise((resolve, reject) => {
			async.retry(retry_opts, async () => {

				this.logger.debug(`Checking status of connection ${id}. Attempt ${++attempts}/${retry_opts.times}`);

				const updated_connection = await this.getConnection(id);
				if (!updated_connection || !updated_connection.state) {
					throw new Error('Connection state could not be determined');
				} else if ([ 'connected', 'rejected' ].indexOf(updated_connection.state) >= 0) {
					return updated_connection;
				} else {
					throw new Error('Still waiting on connection to be accepted');
				}
			}, (error, accepted_connection) => {
				if (error) {
					this.logger.error(`Failed to establish connection ${id}: ${error}`);
					return reject(new Error(`Connection ${id} failed: ${error}`));
				}

				this.logger.info(`Connection ${id} successfully established with agent ${accepted_connection.remote.pairwise.did}`);
				resolve (accepted_connection);
			});
		});
	}

	// TODO what about connection invitations

	//*********************************************************************************
	// CREDENTIALS
	//*********************************************************************************

	/**
	 * Represents the state of a {@link Credential} on the agent.  The state of a credential changes depending on whether
	 * a holder or an issuer is viewing the credential.  For example, if a holder creates the credential request, they will
	 * see the state of the credential as 'outbound_request', while the issuer will see 'inbound_request'.
	 * @typedef {'outbound_request'|'inbound_request'|'outbound_offer'|'inbound_offer'|'accepted'|'rejected'|'issued'|'stored'} CredentialState
	 */

	/**
	 * A Credential starts out as either an outbound_request, if created by a holder, or an outbound_offer, if created by
	 * an issuer. The state transitions for a credential as implemented by cloud agent are as follows:
	 * outbound_request (holder) ->
	 * inbound_request (issuer) ->
	 * outbound_offer (issuer) ->
	 * inbound_offer (holder) ->
	 * accepted OR rejected (holder) ->
	 * issued (issuer) ->
	 * stored (holder)
	 *
	 * @typedef {object} Credential
	 * @property {object} [offer] List the data contained in the credential.  Only present once the credential has reached the offer state.
	 * @property {object} offer.attributes Lists the `<string>: <string>` pairs for all the fields in the credentials. The
	 * list of fields comes from the schema the credential is based on.
	 * @property {string} offer.data The full JSON data for the credential encoded as a string.
	 * @property {string} schema_name The schema that the credential is based on. Ex. "drivers_license"
	 * @property {string} schema_version The version of the schema. Ex. "1.0"
	 * @property {CredentialState} state The current state of the credential.  This is the field you must update to turn credential offers
	 * into stored credentials.
	 * @property {string} id The identifier for the credential on the agent.
	 * @property {object} properties Extra metadata about the credential.  Used for things like sorting and decorating
	 * credentials.
	 * @property {string} [properties.time] We use a `time` property to sort credentials based on when they were offered.
	 * @property {string} [properties.name] An optional friendly name to display when someone looks at the credential offer.
	 * @property {ImageData} [properties.icon] An optional icon to display when someone looks at the credential.
	 * @property {string} role The agent's relationship to the credential.  Either 'holder' or 'issuer'.
	 * @property {CredentialDefinitionID} credential_definition_id The credential definition for this credential.
	 * @property {DID} issuer_did The Issuer's public DID.
	 * @property {object} to Describes the recipient of the initial credential request (holder initiated) or offer
	 * (issuer initiated).  Has either `url` or `name`.
	 * @property {AgentName} [to.name] The {@link AgentName} of the holder.
	 * @property {AgentURL} [to.url] The {@link AgentURL} of the holder.
	 */

	/**
	 * Get a {@link Credential}.
	 * @param {string} id The ID of the credential.
	 * @return {Promise<Credential>} A promise that resolves with the credential information.
	 */
	async getCredential (id) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Invalid credential ID');

		this.logger.info(`Looking up credential ${id}`);
		const r = await this.request('credentials/' + id);
		this.logger.debug('Result from getCredential: '+jsonPrint(r));
		return r;
	}

	/**
	 * An object listing [BSON query parameters]{@link https://docs.mongodb.com/manual/reference/operator/query/} that
	 * correspond to the fields in a {@link Credential} object. The keys listed below are simply examples to give you
	 * the idea; there are others.
	 * @typedef {object} CredentialQueryParams
	 * @property {CredentialState} [state] The connection state we're searching for.
	 * @property {AgentName} ['to.name'] The name of the remote agent .
	 * @property {CredentialDefinitionID} [credential_definition_id] The credential definition.
	 * {
	 *     state: 'inbound_offer',
	 *     credential_definition_id: 'JeU3p99QCt3p5tjZJyPwUK:3:CL:357:TAG1',
	 *     'to.name': 'test-holder'
	 * }
	 */

	/**
	 * Gets a list of all the {@link Credential}s on the agent that match the given search parameters, or all of the credentials
	 * on the agent, if no parameters are given.
	 * @param {CredentialQueryParams} [opts] Optional search parameters for the credentials
	 * @return {Promise<Credential[]>} A promise that resolves with a list of credentials
	 */
	async getCredentials (opts) {
		let query = '';
		if (opts) {
			if (typeof opts !== 'object')
				throw new TypeError('Invalid query parameters');
			query = `?filter=${JSON.stringify(opts)}`;
		}

		this.logger.info('Getting credentials');
		this.logger.debug(`getCredentials query: ${query}`);
		let r = await this.request(`credentials${query}`);
		if (r.items) r = r.items;
		this.logger.info(`Got ${r.length} credentials`);
		this.logger.debug(`Result from getCredentials for query ${query}: ${jsonPrint(r)}`);
		return r;
	}

	/**
	 * Delete a {@link Credential}.
	 *
	 * @param {string} id The ID of an existing credential or credential offer.
	 * @return {Promise<void>} A promise that resolves when the credential is deleted.
	 */
	async deleteCredential (id) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Invalid credential ID');

		this.logger.info(`Deleting credential ${id}`);
		const r = await this.request('credentials/' + id, {
			'method': 'DELETE'
		});
		this.logger.info(`Deleted credential ${id}`);
		this.logger.debug('Result from deleteCredential: '+jsonPrint(r));
	}

	/**
	 * Contains fields necessary to lookup a {@link CredentialSchema}.
	 * @typedef {object} SchemaIDObj
	 * @property {string} schema_name The name of the schema. Ex. "drivers_license", "Driver's License", etc.
	 * @property {string} schema_version The version of the schema. Ex. "1.0", "0.0.1", etc.
	 */

	/**
	 * Describes the recipient of a {@link Verification} or a {@link Credential}.  It must specify either `name` or `did` of an agent
	 * that you have a {@link Connection} with.  The {@link AgentName} can only be used to refer to agents that are in
	 * the same account as this agent.
	 * @typedef {object} RequestRecipient
	 * @property {DID} [did] The `remote.pairwise.did` of other agent in your shared {@link Connection}.
	 * @property {AgentName} [name] The name of an agent in your account.
	 */

	/**
	 * Creates a {@link Credential} and sends the credential request to a remote agent.
	 * @param {RequestRecipient} to The issuer of the desired credential.
	 * @param {SchemaIDObj} source Specifies the schema you'd like the credential to be based on.
	 * @param {Properties} [properties] Optional metadata to add to the credential request.
	 * @return {Promise<Credential>} The created credential request.
	 */
	async requestCredential (to, source, properties) {
		if (!to || !to.did && !to.name)
			throw new TypeError('Must specify an agent name or agent url to send a credential request');
		if (to.did && to.name)
			throw new TypeError('Must specify only an agent name or an agent url for a credential request, not both');
		if (to.did && typeof to.did !== 'string')
			throw new TypeError('Invalid agent url for credential request');
		if (to.name && typeof to.name !== 'string')
			throw new TypeError('Invalid agent name for credential request');

		if (!source || !source.schema_name || typeof source.schema_name !== 'string')
			throw new TypeError('Invalid schema name for requesting a credential');
		if (!source.schema_version || typeof source.schema_version !== 'string')
			throw new TypeError('Invalid schema version for requesting a credential');

		if (properties && typeof properties !== 'object')
			throw new TypeError('Invalid properties for credential offer');

		const body = {
			state: 'outbound_request',
			to: to,
			schema_name: source.schema_name,
			schema_version: source.schema_version,
			properties: properties ? properties : {}
		};

		// Add an optional friendly name to the request
		if (this.name && !body.properties.name) body.properties.name = this.name;

		// It's useful to timestamp offers so you can sort them by most recent
		if (!body.properties.time) body.properties.time = (new Date()).toISOString();

		this.logger.info(`Requesting a ${source.schema_name}:${source.schema_version} credential from ${JSON.stringify(to)}`);
		const r = await this.request('credentials', {
			'method': 'POST',
			'body': JSON.stringify(body)
		});
		this.logger.info(`Creating credential request ${r.id} with ${JSON.stringify(to)}`);
		this.logger.debug('Result from requestCredential: '+jsonPrint(r));
		return r;
	}

	/**
	 * Create a {@Credential} as an offer to the given holder.
	 *
	 * @param {RequestRecipient} to The agent being issued a credential.
	 * @param {CredentialDefinitionID|SchemaIDObj} source The schema or cred def the credential is based on.
	 * @param {object} attributes The `<string>: <string>` pairs for all the fields in the credentials. The
	 * list of fields comes from the schema the credential is based on.
	 * @param {Properties} [properties] Optional metadata to add to the credential offer.
	 * @returns {Promise<Credential>} A promise that resolves with the credential offer.
	 */
	async offerCredential (to, source, attributes, properties) {
		if (!to || !to.did && !to.name)
			throw new TypeError('Must specify an agent name or agent url to send a credential offer');
		if (to.did && to.name)
			throw new TypeError('Must specify only an agent name or an agent url for a credential offer, not both');
		if (to.did && typeof to.did !== 'string')
			throw new TypeError('Invalid agent url for credential offer');
		if (to.name && typeof to.name !== 'string')
			throw new TypeError('Invalid agent name for credential offer');

		if (!attributes || typeof attributes !== 'object' || Object.keys(attributes).length <= 0)
			throw new TypeError('Invalid credential attributes for credential offer');
		for (const key in attributes) {
			if (typeof attributes[key] !== 'string')
				throw new TypeError(`Invalid credential attribute for credential offer: key: ${key}, value: ${attributes[key]}`);
		}

		if (properties && typeof properties !== 'object')
			throw new TypeError('Invalid properties for credential offer');

		const body = {
			state: 'outbound_offer',
			to: to,
			attributes: attributes,
			properties: properties ? properties : {}
		};
		if (!body.properties.time) body.properties.time = (new Date()).toISOString();
		if (this.name && !body.properties.name) body.properties.name = this.name;

		if (typeof source === 'object') {
			// Assume a schema is being used as the source for the credential
			if (!source.schema_name || typeof source.schema_name !== 'string')
				throw new TypeError('Invalid schema name for credential offer');
			if (!source.schema_version || typeof source.schema_version !== 'string')
				throw new TypeError('Invalid schema version for credential offer');
			body.schema_name = source.schema_name;
			body.schema_version = source.schema_version;
		} else if (source && typeof source === 'string') {
			// Assume a credential definition is being used as the source for the credential
			body.credential_definition_id = source;
		} else {
			throw new TypeError('Invalid source for credential offer');
		}

		this.logger.info(`Offering credential based on ${JSON.stringify(source)} to ${JSON.stringify(to)}`);
		const r = await this.request('credentials', {
			'method': 'POST',
			'body': JSON.stringify(body)
		});
		this.logger.info(`Offered credential ${r.id} to ${JSON.stringify(to)}`);
		this.logger.debug('Result from offerCredential: '+jsonPrint(r));
		return r;
	}

	/**
	 * Updates a credential.  You'll really only use this method to accept a credential offer as a holder or fulfill a
	 * credential request as an issuer.
	 *
	 * Accepting a credential offer:
	 * agent.updateCredential(cred_id, 'accepted')
	 *
	 * Fulfilling a credential request:
	 * agent.updateCredential(cred_id, 'outbound_offer', {
	 *     first_name: 'John',
	 *     last_name: 'Doe'
	 * }
	 * @param {string} id The credential ID on the agent.
	 * @param {CredentialState} state The updated state of the credential.
	 * @param {object} [attributes] The filled out information for the credential.  Only required when changing the state
	 * to 'outbound_offer'.
	 * @return {Promise<Credential>} A promise that resolves with the updated credential data.
	 */
	async updateCredential (id, state, attributes) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Invalid credential ID');
		if (!state || typeof state !== 'string')
			throw new TypeError('Invalid connection state');

		const body = {
			state: state
		};

		// Accepting a credential request requires filling out the attributes for a credential
		if (state === 'outbound_offer') {
			if (!attributes || typeof attributes !== 'object' || Object.keys(attributes).length <= 0)
				throw new TypeError('Invalid credential attributes.');
			for (const key in attributes) {
				if (typeof attributes[key] !== 'string')
					throw new TypeError(`Invalid credential attribute: key: ${key}, value: ${attributes[key]}`);
			}

			body.attributes = attributes;
		}

		this.logger.info(`Updating credential ${id} to state ${state}`);
		const r = await this.request('credentials/' + id, {
			'method': 'PATCH',
			'body': JSON.stringify(body)
		});
		this.logger.info(`Updated credential ${id} to state ${state}`);
		this.logger.debug('Result from updateCredential: '+jsonPrint(r));
		return r;
	}


	/**
	 * Waits for a given {@link Credential} to enter the 'issued' or 'rejected' states.
	 *
	 * @param {string} id The ID of a credential.
	 * @param {number} [retries] The number of times we should check the status of the credential before giving up.
	 * @param {number} [retry_interval] The amount of time, in milliseconds, to wait between checks.
	 * @returns {Promise<Credential>} A promise that resolves with the finished credential.
	 */
	async waitForCredential (id, retries, retry_interval) {

		let attempts = 0;
		const retry_opts = {
			times: retries ? retries : 30,
			interval: retry_interval ? retry_interval : 3000,
			errorFilter: (error) => {
				// We should stop if the error was something besides still waiting for the credential.
				return error.toString().toLowerCase().indexOf('waiting') >= 0;
			}
		};

		return new Promise((resolve, reject) => {
			async.retry(retry_opts, async () => {

				this.logger.debug(`Checking status of credential offer ${id}. Attempt ${++attempts}/${retry_opts.times}`);

				const updated_credential = await this.getCredential(id);
				if (!updated_credential || !updated_credential.state) {
					throw new Error('Credential state could not be determined');
				} else if ([ 'issued', 'rejected' ].indexOf(updated_credential.state) >= 0) {
					return updated_credential;
				} else {
					throw new Error('Still waiting on Credential to be accepted');
				}
			}, (error, accepted_credential) => {
				if (error) {
					this.logger.error(`Failed to issue credential ${id}: ${error}`);
					return reject(new Error(`Credential issuance ${id} failed: ${error}`));
				}

				this.logger.info(`Credential ${accepted_credential.id} successfully issued to agent ${JSON.stringify(accepted_credential.to)}`);
				resolve (accepted_credential);
			});
		});
	}

	//*********************************************************************************
	// VERIFICATION
	//*********************************************************************************

	/**
	 * Represents the state of a {@link Verification} on the agent.  The state of a verification changes depending on
	 * whether a prover or a verifier is viewing the verification.  For example, if a prover creates a verification request,
	 * they will see the state of the verification as 'outbound_verification_request', while the issuer will see
	 * 'inbound_verification_request'.
	 * @typedef {'outbound_verification_request'|'inbound_verification_request'|'outbound_proof_request'|'inbound_proof_request'|'proof_generated'|'proof_shared'|'passed'|'failed'} VerificationState
	 */

	/**
	 * Represents all verification and proof requests between a prover and a verifier.  If created by the prover, the
	 * verifications initial state should be "outbound_verification_request".  If created by a verifier, the initial state
	 * should be "outbound_proof_request" by the verifier. The state transitions for a verification from initial request
	 * to a verified or unverified proof are as follows :
	 * outbound_verification_request (prover) ->
	 * inbound_verification_request (verifier) ->
	 * outbound_proof_request (verifier) ->
	 * inbound_proof_request (prover) ->
	 * proof_generated (prover) ->
	 * proof_shared (prover) ->
	 * proof_shared (verifier) ->
	 * passed OR failed (verifier) ->
	 * passed OR failed (prover)
	 *
	 * @typedef {object} Verification
	 * @property {VerificationState} state The current state of the verification.
	 * @property {boolean} [allow_proof_request_override] If true, the prover can supply their own updated proof_request
	 * in the proof_generated phase. Can only be set by the verifier in the outbound_proof_request phase.
	 * @property {Choices} [choices] The list of options for generating a proof from the credentials in an agent's wallet.
	 * Only appears in the `outbound_proof_request` phase.
	 * @property {ProofSchema} proof_request The proof schema the verification is based on.
	 */

	/**
	 * Get the information for a {@link Verification}.
	 * @param {string} id The ID of the verification.
	 * @return {Promise<Verification>} A promise that resolves with the verification information.
	 */
	async getVerification (id) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Invalid verification id');

		this.logger.info(`Looking up verification ${id}`);
		const r = await this.request('verifications/' + id);
		this.logger.info(`Got verification ${r.id}`);
		this.logger.debug('Result from getVerification: '+jsonPrint(r));
		return r;
	}

	/**
	 *  An object listing [BSON query parameters]{@link https://docs.mongodb.com/manual/reference/operator/query/} that
	 * correspond to the fields in a {@link Verification} object. The keys listed below are simply examples to give you
	 * the idea; there are others.
	 * @typedef {object} VerificationQueryParams
	 * @property {string} ['to.name'] The party that the initial verification was sent to in the outbound_verification_request
	 * or outbound_proof_request phase.
	 * @property {VerificationState} [state] The state of the verifications.
	 * {
	 *     state: 'inbound_offer',
	 *     'to.name': { $neq: 'test-holder'}
	 * }
	 */

	/**
	 * Get a list of all the {@link Verification}s on the agent, or a subset of verifications that match the search
	 * parameters.
	 * @param {VerificationQueryParams} [opts] Search parameters.
	 * @return {Promise<Verification[]>} A promise that resolves with a list of matching verifications.
	 */
	async getVerifications (opts) {
		let query = '';
		if (opts) {
			if (typeof opts !== 'object')
				throw new TypeError('Invalid query parameters');
			query = `?filter=${JSON.stringify(opts)}`;
		}

		this.logger.info('Getting verifications');
		this.logger.debug(`getVerifications query: ${query}`);
		let r = await this.request(`verifications${query}`);
		if (r.items) r = r.items;
		this.logger.info(`Got ${r.length} verifications`);
		this.logger.debug(`Result from getVerifications for query ${query}: ${jsonPrint(r)}`);
		return r;
	}

	/**
	 * Delete a {@link Verification}.
	 * @param {string} id The ID of the verification.
	 * @return {Promise<void>} A promise the resolves when the verification is deleted.
	 */
	async deleteVerification (id) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Invalid verification ID');

		this.logger.info(`Deleting verification ${id}`);
		const r = await this.request('verifications/' + id, {
			'method': 'DELETE'
		});
		this.logger.info(`Deleted verification ${id}`);
		this.logger.debug('Result from deleteVerification: '+jsonPrint(r));
		return r;
	}

	/**
	 * Creates a {@link Verification} with another agent.  The initial state must be one of 'outbound_proof_request',
	 * 'outbound_verification_request'.
	 * @param {RequestRecipient} to The agent being contacted for verification.
	 * @param {string} proof_schema_id The proof schema the verification is based on.
	 * @param {VerificationState} state The initial state of the verification.
	 * @param {Properties} [properties] Optional metadata to add to the verification.
	 * @returns {Promise<Verification>} A promise that resolves with the created verification.
	 */
	async createVerification (to, proof_schema_id, state, properties) {
		if (!to || !to.did && !to.id)
			throw new TypeError('Must specify an agent id or agent did to send a verification');
		if (to.did && to.id)
			throw new TypeError('Must specify only an agent id or an agent did for a verification, not both');
		if (to.did && typeof to.did !== 'string')
			throw new TypeError('Invalid agent did for verification');
		if (to.id && typeof to.id !== 'string')
			throw new TypeError('Invalid agent name for verification');

		if (!proof_schema_id || typeof proof_schema_id !== 'string')
			new TypeError('Invalid proof schema information for verification');

		const valid_states = [ 'outbound_proof_request', 'outbound_verification_request' ];
		if (valid_states.indexOf(state) < 0)
			throw new Error(`New verification state was not one of ${JSON.stringify(valid_states)}`);

		const body = {
			state: state,
			to: to,
			proof_schema_id: proof_schema_id,
			properties: properties ? properties : {}
		};
		if (this.name && !body.properties.name)
			body.properties.name = this.name;

		if (!body.properties.time)
			body.properties.time = (new Date()).toISOString();

		this.logger.info(`Creating a verification based on ${proof_schema_id} with ${JSON.stringify(to)}`);
		const r = await this.request('verifications', {
			'method': 'POST',
			'body': JSON.stringify(body)
		});
		this.logger.info(`Created verification ${r.id} on ${proof_schema_id} with ${JSON.stringify(to)}`);
		this.logger.debug('Result from createVerification: '+jsonPrint(r));
		return r;
	}

	/**
	 * Describes data that could be used to fill out a requested attribute in a proof request.  It's data describes
	 * information from a single credential in the agent's wallet.
	 * @typedef {object} PredicateChoice
	 * @property {string} predicate The predicate calculated from the corresponding {@link Credential}.
	 * @property {CredentialDefinitionID} cred_def_id The credential definition the corresponding credential was issued under.
	 * @property {CredentialSchemaID} schema_id The schema that the credential is based on.
	 * {
		   'predicate': 'average GE 10',
		   'cred_def_id': 'Up36FJDNu3YGKvhTJAiZQU:3:CL:31:TAG1',
		   'schema_id': 'EDEuxdBQ3zb6GzWKCNcyW4:2:Transcript:1.0'
		}
	 */

	/**
	 * Describes data that could be used to fill out a requested attribute in a proof request.  It's data describes
	 * information from a single credential in the agent's wallet.
	 * @typedef {object} AttributeChoice
	 * @property {string} name The name of the attribute.
	 * @property {string} value The value of the attribute.
	 * @property {CredentialDefinitionID} cred_def_id The credential definition the corresponding credential was issued under.
	 * @property {CredentialSchemaID} schema_id The schema that the credential is based on.
	 * {
		   'name': 'first_name',
		   'value': 'Alice',
		   'cred_def_id': 'Up36FJDNu3YGKvhTJAiZQU:3:CL:31:TAG1',
		   'schema_id': 'EDEuxdBQ_3zb6GzWKCNcyW4:2:Transcript:1.0'
		}
	 */

	/**
	 * Describes a list of {@link AttributeChoice}s for filling out the requested attributes and predicates from a
	 * {@link Verification}'s {@link ProofSchema}.  When generating the proof, the choices can be condensed into a
	 * {@link ProofSelection} and passed to the API to control what credentials are used to generate the proof.
	 *
	 * @typedef {object} Choices
	 * @property {object} attributes A list of requested attributes.  The next field is an example.
	 * @property {object<string,AttributeChoice>} [attr1] A list of {@link AttributeChoice}s.
	 * @property {object} predicates A list of requested predicates. The next field is an example.
	 * @property {object<string,PredicateChoice>} [pred1] A list of {@link PredicateChoice}s.
	 * {
		   'choices': {
			  'attributes': {
				 '<attr1>': {
					'<attr1_choice1>': {
					   'name': 'first_name',
					   'value': 'Alice',
					   'cred_def_id': 'Up36FJDNu3YGKvhTJAiZQU:3:CL:31:TAG1',
					   'schema_id': 'EDEuxdBQ_3zb6GzWKCNcyW4:2:Transcript:1.0'
					},
					'<attr1_choice2>': {
					   'name': 'first_name',
					   'value': 'Alice',
					   'cred_def_id': 'Up36FJDNu3YGKvhTJAiZQU:3:CL:31:TAG1',
					   'schema_id': 'EDEuxdBQ3zb6GzWKCNcyW4:2:Transcript:1.0'
					}
				 }
			  },
			  'predicates': {
				 '<pred1>': {
					'<pred1_choice1>': {
					   'predicate': 'average GE 10',
					   'cred_def_id': 'Up36FJDNu3YGKvhTJAiZQU:3:CL:31:TAG1',
					   'schema_id': 'EDEuxdBQ3zb6GzWKCNcyW4:2:Transcript:1.0'
					}
				 }
			  }
		   }
		}
	 */

	/**
	 * A list of {@link AttributeChoice}s and {@link PredicateChoice}s that should be used in the `generate_proof` phase
	 * of a {@link Verification}.
	 * @typedef {object} ProofSelection
	 * @property {object<string,AttributeChoice>} attributes A list of requested attributes and their selected credential attributes.
	 * @property {object<string,PredicateChoice>} prediecates A list of requested predicates and their selected predicates.
	 *  {
		  "attributes": {
			"<attr1>": "<attr1_choice2>"
		  },
		  "predicates": {
			"<pred1>": "<pred1_choice1>"
		  }
		}
	 */

	/**
	 * Updates a {@link Verification}.  A verifier accepts a `inbound_verification_request` by updating the state to
	 * `outbound_proof_request`.  The prover generates a proof for a `inbound_proof_request` by updating the state to
	 * `proof_generated`.  The prover submits that generated proof request by updating the state to `proof_shared`.
	 *
	 * Sometimes, you have a selection
	 * @param {string} id The verification ID.
	 * @param {VerificationState} state The updated verification state.
	 * @param {ProofSelection} [choices] The list of credentials you want to use for requested attributes and predicates.
	 * @param {object<string, string>} [self_attested_attributes] The self-attested data to add to the proof.
	 * @returns {Promise<Verification>} A Promise that resolves with the updated verification.
	 */
	async updateVerification (id, state, choices, self_attested_attributes) {
		if (!id ||typeof id !== 'string')
			throw new TypeError('Invalid verification ID');
		if (!state || typeof state !== 'string')
			throw new TypeError('Invalid state for updating verification');
		if (choices && typeof choices !== 'object')
			throw new TypeError('Invalid credential selections for building proof');
		if (self_attested_attributes && typeof self_attested_attributes !== 'object')
			throw new TypeError('Invalid self attested attributes list for building proof');

		const body = {
			state: state,
		};

		if (choices) body.choices = choices;
		if (self_attested_attributes) body.self_attested_attributes = self_attested_attributes;

		this.logger.info(`Updating verification ${id} to state ${state}`);
		const r = await this.request('verifications/' + id, {
			'method': 'PATCH',
			'body': JSON.stringify(body)
		});
		this.logger.debug('Result from proverGenerateProof: '+jsonPrint(r));
		return r;
	}

	/**
	 * Waits for a given {@link Verification} to enter the `passed` or `failed` state.
	 * @param {string} id The verification ID.
	 * @param {number} [retries] The number of times we should check the status of the verification before giving up.
	 * @param {number} [retry_interval] The amount of time, in milliseconds, to wait between checks.
	 * @returns {Promise<Verification>} A promise that resolves with the completed verification.
	 */
	async waitForVerification (id, retries, retry_interval) {

		let attempts = 0;
		const retry_opts = {
			times: retries ? retries : 30,
			interval: retry_interval ? retry_interval : 3000,
			errorFilter: (error) => {
				// We should stop if the error was something besides still waiting for the credential.
				return error.toString().toLowerCase().indexOf('waiting') >= 0;
			}
		};

		return new Promise((resolve, reject) => {
			async.retry(retry_opts, async () => {

				this.logger.debug(`Checking status of verification ${id}. Attempt ${++attempts}/${retry_opts.times}`);

				const updated_verification = await this.getVerification(id);
				if (!updated_verification || !updated_verification.state) {
					throw new Error('Verification state could not be determined');
				} else if ([ 'passed', 'failed' ].indexOf(updated_verification.state) >= 0) {
					return updated_verification;
				} else {
					throw new Error('Still waiting on Verification to be accepted');
				}
			}, (error, accepted_verification) => {
				if (error) {
					this.logger.error(`Failed to complete verification ${id}: ${error}`);
					return reject(new Error(`Verification ${id} failed: ${error}`));
				}

				this.logger.info(`Verification ${accepted_verification.id} was completed`);
				resolve (accepted_verification);
			});
		});
	}

	//*********************************************************************************
	// MESSAGES
	//*********************************************************************************

	/**
	 * Basic messages represent a way for one agent to exchange information with another agent.
	 *
	 * @typedef {object} Message
	 * @property {string} id A unique identifier for this message
	 * @property {string} content The body of the message
	 * @property {string} sent_time A datetime string for when the message was sent.
	 * @property {Connection} connection The connection over which the message travelled.  Contains information about the sender.
	 */

	/**
	 * Gets a {@link Message}.
	 * @param {string} id The ID for a message.
	 * @return {Promise<Message>} A promise that resolves with the given message, or rejects if something went wrong.
	 */
	async getMessage (id) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Message ID must be a string');

		this.logger.info(`Getting message ${id}`);
		const r = await this.request(`messages/${id}`);
		this.logger.info(`Got message ${r.id}`);
		this.logger.debug('Result from getMessage: '+jsonPrint(r));
		return r;
	}

	/**
	 * Delete a {@link Message}.
	 *
	 * @param {string} id The ID of an existing message.
	 * @returns {Promise<void>} A promise that resolves when the message is deleted.
	 */
	async deleteMessage (id) {
		if (!id || typeof id !== 'string')
			throw new TypeError('Message ID was not provided');

		this.logger.info(`Deleting message ${id}`);
		const r = await this.request('messages/' + id, {
			method: 'DELETE'
		});
		this.logger.info(`Deleted message ${id}`);
		this.logger.debug('Result from deleteMessage: '+jsonPrint(r));
	}

	/**
	 * An object listing [BSON query parameters]{@link https://docs.mongodb.com/manual/reference/operator/query/} that
	 * correspond to the fields in a {@link Message} object. The keys listed below are simply examples to give you
	 * the idea; there are others.
	 * @typedef {object} MessageQueryParams
	 * @property {string} id The id of the message that we're searching for.
	 * @property {string} [connection.remote.name] The agent name of the sender.
	 * {
	 *     id: "d058aa41-af0b-4b10-bf67-dcdccaa5da7",
	 *     connection.remote.name: "BBCU"
	 * }
	 */

	/**
	 * Returns a list of {@link Message}s.  If query parameters are provided, only messages matching those parameters will
	 * be returned.  If none are specified, all of the agent's messages will be returned.
	 * @param {MessageQueryParams} [opts] Connections search parameters.
	 * @return {Promise<Message[]>} A list of all messages or only those matching the query parameters.
	 */
	async getMessages (opts) {
		let query = '';
		if (opts) {
			if (typeof opts !== 'object')
				throw new TypeError('Invalid query parameters');
			query = `?filter=${JSON.stringify(opts)}`;
		}

		this.logger.info('Getting messages');
		let r = await this.request(`messages${query}`);
		if (r.items) r = r.items;
		this.logger.info(`Got ${r.length} messages`);
		this.logger.debug(`Result from getMessages for query '${query}': ${jsonPrint(r)}`);
		return r;
	}

	/**
	 * Describes the recipient of a {@link Message}.  It must specify either `name` or `did` of an agent
	 * that you have a {@link Connection} with.  The {@link AgentName} can only be used to refer to agents that are in
	 * the same account as this agent.
	 * @typedef {object} MessageRecipient
	 * @property {string} [id] The `id` of your shared {@link Connection} over which to send the message.
	 * @property {DID} [did] The `remote.pairwise.did` of other agent in your shared {@link Connection}.
	 * @property {AgentName} [name] The `remote.name` of other agent in your shared {@link Connection}.
	 */

	/**
	 * Send a basic message to the given agent
	 * @param {MessageRecipient} to The agent that is to receive the message.
	 * @param {string} content The body of the message to send.
	 * @param {string} locale The locale of the message body.  Default value is "en".
	 * @return {Promise<Invitation>} The created {@link Invitation}.
	 */
	async sendMessage (to, content, locale) {
		if (!to || !to.did && !to.name && !to.id)
			throw new TypeError('Must specify an agent name or agent did or connection id to send a message');
		if ((to.did && to.name) || (to.did && to.id) || (to.id && to.name))
			throw new TypeError('Must specify only an agent name, agent DID or connection id as the recipient of a Message offer, not a combination of them');
		if (to.did && typeof to.did !== 'string')
			throw new TypeError('Invalid agent DID for message');
		if (to.name && typeof to.name !== 'string')
			throw new TypeError('Invalid agent name for message');
		if (to.id && typeof to.id !== 'string')
			throw new TypeError('Invalid connection id for message');

		if (locale && typeof locale !== 'string')
			throw new TypeError('Invalid content for message');

		if (content && typeof content !== 'string')
			throw new TypeError('Invalid content for message');

		const method = 'POST';
		const route = 'messages';
		const body = {
			to: to,
			locale: locale,
			content: content
		};
		this.logger.debug(`Message send parameters: ${jsonPrint(body)}`);
		const r = await this.request(route, {
			method,
			body: JSON.stringify(body)
		});
		this.logger.info(`Sent message ${r.id}`);
		this.logger.debug('Result from sending message: '+jsonPrint(r));
		return r;
	}

	//---------------------------------------------------------------------------------
	// COMMUNICATION
	//*********************************************************************************

	/**
	 * Call Agent REST APIs and make request
	 *
	 * @param {string} path The REST API path
	 * @param {object} [options] Set headers, method=GET, POST, PUT, PATCH, DELETE, UPDATE by passing in object {"headers":{...}, "method":...}
	 * @return {object} The response object.  May be null if request returns no content.
	 */
	async request (path, options) {

		let rAgent;
		if (this.url.indexOf('https') === 0)
			rAgent = new https.Agent({
				rejectUnauthorized: false
			});
		else
			rAgent = new http.Agent({
				rejectUnauthorized: false
			});

		// Make sure the request url has /api/v1 in it
		const parsed_url = new URL(this.url);
		parsed_url.pathname = '/api/v1/';
		const request_url = new URL(path, parsed_url.href);
		this.logger.debug(`Request path: ${request_url}`);
		try {
			options = options || {};
			options.headers = options.headers || {};
			options.headers['Content-Type'] = 'application/json';
			options.headers['Accept'] = 'application/json';
			options.agent = rAgent;
			if (!options.headers['Authorization']) options.headers['Authorization'] = this.authHeader;
			this.logger.debug('Request: ' + request_url + ' ' + jsonPrint(options));
			const fetch_response = await fetch(request_url, options);
			let json_response = null;
			const responseText = await fetch_response.text();
			try {
				json_response = await JSON.parse(responseText);
			} catch (err) {
				this.logger.error(`Fetch response error could not be parsed as JSON: ${err}`);
			}
			if (!fetch_response.ok) {
				let error = json_response;
				if (error && error.message) {
					error = error.message;
				}
				if (!error) {
					error = 'Unknown error';
				}
				const status = fetch_response.status;
				this.logger.error('Error: ' + jsonPrint(error));
				const e = new Error(error);
				e.code = status;
				throw e;
			}
			this.logger.debug('Result from request: ', json_response);
			return json_response;
		} catch (e) {
			this.logger.error('Failure sending request to agent: ' + e.code + ' - ' + e.message);
			throw e;
		}
	}

}

module.exports = {
	Agent: Agent
};
