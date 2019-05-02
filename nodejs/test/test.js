const Agent = require('../sdk').Agent;
const dotenv = require('dotenv');
const expect = require('chai').expect

dotenv.config();

const {
  ACCOUNT_URL: accountUrl,
  ISSUER_AGENT_NAME: issuerName,
  ISSUER_AGENT_PASSWORD: issuerPassword,
  HOLDER_AGENT_NAME: holderName,
  HOLDER_AGENT_PASSWORD: holderPassword,
  VERIFIER_AGENT_NAME: verifierName,
  VERIFIER_AGENT_PASSWORD: verifierPassword,
} = process.env;

const logLevel = 'disabled';

const holder = new Agent(`https://${accountUrl}`, holderName, holderPassword, holderName, logLevel);
let holderIdentity;

const issuer = new Agent(`https://${accountUrl}`, issuerName, issuerPassword, issuerName, logLevel);
let issuerIdentity;

const verifier = new Agent(`https://${accountUrl}`, verifierName, verifierPassword, verifierName, logLevel);
let verifierIdentity;

describe('sdk', () => {

  before(async () => {
    
    holderIdentity = await holder.getIdentity();
    issuerIdentity = await issuer.getIdentity();
    verifierIdentity = await verifier.getIdentity();
  });

  it(`should get identity for holder '${holderName}'`, async () => {
    checkIdentity(holder, holderIdentity);
  });

  it(`should get identity for issuer '${issuerName}'`, async () => {
    checkIdentity(issuer, issuerIdentity);
  });

  it(`should get identity for verfier '${verifierName}'`, async () => {
    checkIdentity(verifier, verifierIdentity);
  });

  // tests a holder initiated connection
  it(`should connect '${issuerName}' to '${holderName}'`, async () => {
    const to = { url: issuerIdentity.url }; // create the connection request body

    const holderOffer = await holder.createConnection(to);  // make the connection request
    expect(holderOffer).to.not.be.undefined;
    expect(holderOffer.remote.url).to.be.equal(issuerIdentity.url);

    // check the offers in the issuer's queue
    const issuerOffers = await issuer.getConnections({ state: 'inbound_offer' });
    expect(issuerOffers.length).to.be.greaterThan(0);

    for (const i in issuerOffers) {
      const offer = issuerOffers[i];
      
      // check who requested the connection
      const { remote : { url } } = offer;
      expect(url).to.not.be.undefined;
      
      // check if the offer is the one just made from the holder
      if (url === holderIdentity.ur) {
        await agent.acceptConnection(offer.id)
        break;
      }
    }

    // verify the connections exist
    const holderConnections = await holder.getConnections();
    const issuerConnections = await issuer.getConnections();
    
    expect(holderConnections.length).to.be.greaterThan(0);
    expect(issuerConnections.length).to.be.greaterThan(0);
    
    const connection = holderConnections[holderConnections.length-1]; // assume the connection is at the tail

    expect(connection.remote.url).to.equal(issuerIdentity.url);
    // expect(connection.local.public.did).to.equal(issuerIdentity.did); // TODO is this not accurate?
  });

  it(`should get credentials for ${holderName}`, async () => {
    const credentials = await holder.getCredentials();
    
    expect(credentials).to.not.be.undefined;
    expect(credentials.length).to.be.greaterThan(1);
  });
});

async function checkIdentity (agent, identity) {
  const { user } = agent;
  const { name, url } = identity;

  expect(identity).to.not.be.undefined;
  expect(name).to.equal(user);
  expect(url).to.eql(`https://${user}:@${accountUrl}`);
}
