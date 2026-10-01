// Live verification of the credential the secrets scan found.
//
// A pattern match answers "does this look like a credential?"
// This script answers a different question: "does this credential work?"
//
// It makes a real, signed call to AWS STS. GetCallerIdentity is the right
// operation for the purpose -- it is read-only, it changes nothing, and if the
// credential is live it returns the identity the credential belongs to.
//
// ---------------------------------------------------------------------------
// Why the credentials are passed explicitly
// ---------------------------------------------------------------------------
// The SDK resolves credentials through a chain: explicit client config, then
// environment variables, then shared config files, then the instance metadata
// service. Any of the later links would answer a different question than the
// one being asked -- a result obtained with credentials already present on the
// machine says nothing about the key under test.
//
// Passing them in the client config pins the chain to its first link, so the
// verdict is attributable to this key and nothing else. The script prints the
// key it is about to use, for the same reason: the output should name its
// subject.
//
// ---------------------------------------------------------------------------
// Reading the result
// ---------------------------------------------------------------------------
//   InvalidClientTokenId   the access key ID does not exist in AWS at all
//   SignatureDoesNotMatch  the key ID exists, but the secret is wrong
//   SignatureExpired       the key existed and has been revoked
//   success                the credential is live -- and it has an owner
//
// The distinction between the first two is the whole point. A rejection alone
// does not prove a key is fake; it could be a real key with a bad secret. The
// error name is what separates "not a credential" from "a credential we got
// wrong".

const { STSClient, GetCallerIdentityCommand } = require("@aws-sdk/client-sts");

// AWS's own published example pair, used throughout its documentation. Both
// halves are placeholders; neither has ever been a functioning credential.
const ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

async function main() {
  console.log(`Key under test:  ${ACCESS_KEY_ID}`);
  console.log(`Secret supplied: ${SECRET_ACCESS_KEY.slice(0, 4)}... (${SECRET_ACCESS_KEY.length} characters)`);
  console.log("Credentials are passed explicitly: no environment, profile or IMDS lookup.\n");

  const client = new STSClient({
    region: "us-east-1",
    credentials: {
      accessKeyId: ACCESS_KEY_ID,
      secretAccessKey: SECRET_ACCESS_KEY,
    },
  });

  try {
    const res = await client.send(new GetCallerIdentityCommand({}));
    console.log("RESULT: ACTIVE -- this key is a live credential.");
    console.log(`  Account: ${res.Account}`);
    console.log(`  ARN:     ${res.Arn}`);
    console.log(`  UserId:  ${res.UserId}`);
  } catch (err) {
    console.log("RESULT: INERT -- the call was rejected.");
    console.log(`  name:    ${err.name}`);
    console.log(`  message: ${err.message}`);
    console.log(`  http:    ${err.$metadata && err.$metadata.httpStatusCode}`);
  }
}

main();
