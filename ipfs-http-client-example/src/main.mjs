import dagJose from "dag-jose"; // js-dag-jose still required since most of the
// encoding/decoding happens in JS
import { convert } from "blockcodec-to-ipld-format";
import IPFSClient from "ipfs-http-client";

import CID from "cids";

import { DID } from "dids";
import { Ed25519Provider } from "key-did-provider-ed25519";
import KeyDidResolver from "key-did-resolver";
import didResolver from "did-resolver";
const { Resolver } = didResolver; // sorry about Node.js querks
import { hash } from "@stablelib/sha256";
import { fromString } from "uint8arrays";

function setupIPFS() {
  const format = convert(dagJose.default); // sorry about Node.js querks
  return IPFSClient.create({ ipld: { formats: [format] } });
}

function setupDID() {
  const keyDidResolver = KeyDidResolver.default.getResolver(); // sorry about Node.js querks
  const resolver = new Resolver({
    ...keyDidResolver,
  });

  const seed64 = hash(
    fromString("some secret string to provide entropy".slice(2))
  );
  const seed = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) {
    seed[i] = seed64[i];
  }

  const didProvider = new Ed25519Provider(seed);
  const did = new DID({ provider: didProvider, resolver: resolver });
  return did;
}

function main() {
  const ipfs = setupIPFS();
  const did = setupDID();

  async function addSignedObject(payload) {
    // sign the payload as dag-jose
    const { jws, linkedBlock } = await did.createDagJWS(payload);
    // put the JWS into the ipfs dag
    const jwsCid = await ipfs.dag.put(jws, {
      format: "dag-jose",
      hashAlg: "sha2-256",
      inputEnc: "cbor", // since js-dag-jose uses the cbor input encoding
    });
    // put the payload into the ipfs dag
    await ipfs.block.put(linkedBlock, {
      cid: new CID(jws.link.toString()),
    });
    return jwsCid;
  }

  async function addEncryptedObject(cleartext, dids) {
    const jwe = await did.createDagJWE(cleartext, dids);
    return ipfs.dag.put(jwe, {
      format: "dag-jose",
      hashAlg: "sha2-256",
      inputEnc: "cbor",
    });
  }

  async function followSecretPath(cid) {
    const jwe = (await ipfs.dag.get(cid)).value;
    const cleartext = await did.decryptDagJWE(jwe);
    console.log(cleartext);
    if (cleartext.prev) {
      followSecretPath(cleartext.prev);
    }
  }

  const perform = async () => {
    await did.authenticate();

    // Create our first signed object
    const cid1 = await addSignedObject({ hello: "world" });

    // Log the DagJWS:
    console.log((await ipfs.dag.get(cid1)).value);
    // > {
    // >   payload: "AXESIHhRlyKdyLsRUpRdpY4jSPfiee7e0GzCynNtDoeYWLUB",
    // >   signatures: [{
    // >     signature: "idGMhvijDbTv2-TnEF6bRCE_ycEBZMIBMZh4EJ4u-9q_ITKxuWd4tF5wMVzXmp7m4mvFwomzT8uxkBQhZztgCg",
    // >     protected: "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDprZXk6ejZNa3Nlb3A4bTM2QWhBenJ0MnduaW1LSldScWZ3ckN6Q1JZWVNvdWtwYmQ5Rk1xI3o2TWtzZW9wOG0zNkFoQXpydDJ3bmltS0pXUnFmd3JDekNSWVlTb3VrcGJkOUZNcSJ9"
    // >   }],
    // >   link: CID(bafyreidykglsfhoixmivffc5uwhcgshx4j465xwqntbmu43nb2dzqwfvae)
    // > }

    // Log the payload:
    console.log((await ipfs.dag.get(cid1, { path: "/link" })).value);
    // > { hello: 'world' }

    // Create another signed object that links to the previous one
    const cid2 = await addSignedObject({
      hello: "getting the hang of this",
      prev: cid1,
    });

    // Log the new payload:
    console.log((await ipfs.dag.get(cid2, { path: "/link" })).value);
    // > {
    // >   hello: 'getting the hang of this'
    // >   prev: CID(bagcqcera7hrxuvb5umrxtfk7lkst5dqdvejjfziq6ceebkxytuw54lzureva)
    // > }

    // Log the old payload:
    console.log((await ipfs.dag.get(cid2, { path: "/link/prev/link" })).value);
    // > { hello: 'world' }

    const { value: jws1 } = await ipfs.dag.get(cid1);
    const { value: jws2 } = await ipfs.dag.get(cid2);

    const signingDID1 = await did.verifyJWS(jws1);
    const signingDID2 = await did.verifyJWS(jws2);

    console.log(signingDID1);
    /* Output:
     * {
     *   kid: 'did:key:z6Mkseop8m36AhAzrt2wnimKJWRqfwrCzCRYYSoukpbd9FMq#z6Mkseop8m36AhAzrt2wnimKJWRqfwrCzCRYYSoukpbd9FMq',
     *   payload: undefined,
     *   didResolutionResult: {
     *     didResolutionMetadata: { contentType: 'application/did+json' },
     *     didDocument: {
     *       id: 'did:key:z6Mkseop8m36AhAzrt2wnimKJWRqfwrCzCRYYSoukpbd9FMq',
     *       verificationMethod: [Array],
     *       authentication: [Array],
     *       assertionMethod: [Array],
     *       capabilityDelegation: [Array],
     *       capabilityInvocation: [Array],
     *       keyAgreement: [Array]
     *     },
     *     didDocumentMetadata: {}
     *   }
     * }
     */
    console.log(signingDID2);
    /* Output:
     * {
     *   kid: 'did:key:z6Mkseop8m36AhAzrt2wnimKJWRqfwrCzCRYYSoukpbd9FMq#z6Mkseop8m36AhAzrt2wnimKJWRqfwrCzCRYYSoukpbd9FMq',
     *   payload: undefined,
     *   didResolutionResult: {
     *     didResolutionMetadata: { contentType: 'application/did+json' },
     *     didDocument: {
     *       id: 'did:key:z6Mkseop8m36AhAzrt2wnimKJWRqfwrCzCRYYSoukpbd9FMq',
     *       verificationMethod: [Array],
     *       authentication: [Array],
     *       assertionMethod: [Array],
     *       capabilityDelegation: [Array],
     *       capabilityInvocation: [Array],
     *       keyAgreement: [Array]
     *     },
     *     didDocumentMetadata: {}
     *   }
     * }
     */

    const cid3 = await addEncryptedObject({ hello: "secret" }, [did.id]);
    const cid4 = await addEncryptedObject({ hello: "cool!", prev: cid3 }, [
      did.id,
    ]);

    // Retrieve a single object
    followSecretPath(cid3);
    // > { hello: 'secret' }

    // Retrive multiple linked objects
    followSecretPath(cid4);
    // > { hello: 'cool!', prev: CID(bagcqcerakmciuwaqugkzuna2ucpzvqzuocubxb6f3gm3epsdibe4lxta25hq) }
    // > { hello: 'secret' }
  };
  perform();
}

main();
