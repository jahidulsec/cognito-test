const express = require("express");
const bodyParser = require("body-parser");
const {
  SignUpCommand,
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  ConfirmSignUpCommand,
  AuthFlowType,
  ChallengeNameType,
  RespondToAuthChallengeCommand,
  GetUserCommand,
  AdminInitiateAuthCommand,
} = require("@aws-sdk/client-cognito-identity-provider");
const crypto = require("crypto");
const dotenv = require("dotenv");
const { CognitoJwtVerifier } = require("aws-jwt-verify");

dotenv.config();

const CLIENT_ID = process.env.AWS_CLIENT_ID;
const CLIENT_SECRET = process.env.AWS_CLIENT_SECRET;

const client = new CognitoIdentityProviderClient({
  region: "eu-north-1",
});

const verifier = CognitoJwtVerifier.create({
  userPoolId: process.env.AWS_USER_POOL_ID,
  tokenUse: "access",
  clientId: CLIENT_ID,
});

const app = express();
const port = 3000;

function getSecretHash(username, clientId, clientSecret) {
  return crypto
    .createHmac("sha256", clientSecret)
    .update(`${username}${clientId}`)
    .digest("base64");
}

app.use(bodyParser.json());

app.post("/signup", async (req, res) => {
  const { username, password, email, phone_number, name } = req.body;

  const command = new SignUpCommand({
    ClientId: CLIENT_ID,
    SecretHash: getSecretHash(username, CLIENT_ID, CLIENT_SECRET),
    Username: username,
    Password: password,
    UserAttributes: [
      {
        Name: "email",
        Value: email,
      },
      {
        Name: "phone_number",
        Value: phone_number,
      },
      {
        Name: "name",
        Value: name,
      },
    ],
  });

  try {
    const data = await client.send(command);
    res.json(data);
  } catch (error) {
    res.status(400).json(error);
  }
});

app.post("/confirm", async (req, res) => {
  const { username, confirmationCode } = req.body;

  const params = new ConfirmSignUpCommand({
    ClientId: CLIENT_ID,
    SecretHash: getSecretHash(username, CLIENT_ID, CLIENT_SECRET),
    Username: username,
    ConfirmationCode: confirmationCode,
  });

  try {
    const response = await client.send(params);
    res.json(response);
  } catch (error) {
    res.status(400).json(error);
  }
});

app.post("/signin-mobile", async (req, res) => {
  const { username } = req.body;

  const params = new InitiateAuthCommand({
    AuthFlow: AuthFlowType.USER_AUTH,
    ClientId: CLIENT_ID,
    AuthParameters: {
      USERNAME: username,
      PREFERRED_CHALLENGE: ChallengeNameType.SMS_OTP,
      // PASSWORD: password,  //
      SECRET_HASH: getSecretHash(username, CLIENT_ID, CLIENT_SECRET),
    },
    // ChallengeName: ChallengeNameType.SMS_OTP,
    // ChallengeParameters: {
    //   // USERNAME: username,
    // }
  });

  try {
    const data = await client.send(params);
    console.log(data);
    res.json(data);
  } catch (error) {
    res.status(400).json(error);
  }
});

app.post("/signin", async (req, res) => {
  const { username, password } = req.body;

  const params = new InitiateAuthCommand({
    AuthFlow: AuthFlowType.USER_PASSWORD_AUTH,
    ClientId: CLIENT_ID,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password, //
      SECRET_HASH: getSecretHash(username, CLIENT_ID, CLIENT_SECRET),
    },
  });

  try {
    const data = await client.send(params);
    console.log(data);
    res.json(data);
  } catch (error) {
    res.status(400).json(error);
  }
});

app.post("/otp", async (req, res) => {
  const { username, code, session } = req.body;

  const params = new RespondToAuthChallengeCommand({
    AuthFlow: AuthFlowType.USER_AUTH,
    ClientId: CLIENT_ID,
    ChallengeName: ChallengeNameType.SMS_OTP,
    ChallengeResponses: {
      SMS_OTP_CODE: code,
      USERNAME: username,
      SECRET_HASH: getSecretHash(username, CLIENT_ID, CLIENT_SECRET),
    },
    UserPoolId: "eu-north-1_l98JHU8zj",
    Session: session,
  });

  // ------ ID TOKEN -------

  // {
  //   "sub": "504c892c-d0e1-707b-1826-07faa5d0c474",
  //   "cognito:groups": [
  //     "user"
  //   ],
  //   "email_verified": true,
  //   "iss": "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_l98JHU8zj",
  //   "phone_number_verified": true,
  //   "cognito:username": "fahim",
  //   "origin_jti": "2c335d24-eeb7-48e4-9ace-26eb863681c0",
  //   "aud": "146cabl46h8eueupc5ff5h60i1",
  //   "event_id": "dc59939a-2747-43ca-b568-b02e14c0165b",
  //   "token_use": "id",
  //   "auth_time": 1733291810,
  //   "name": " islam",
  //   "phone_number": "+8801785945968",
  //   "exp": 1733295410,
  //   "iat": 1733291810,
  //   "jti": "b2e7d607-b570-4092-b734-225c5d8f34bf",
  //   "email": "2ejahid@gmail.com"
  // }

  //  ------ ACCESS TOKEN --------

  // {
  //   "sub": "504c892c-d0e1-707b-1826-07faa5d0c474",
  //   "cognito:groups": [
  //     "user"
  //   ],
  //   "iss": "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_l98JHU8zj",
  //   "client_id": "146cabl46h8eueupc5ff5h60i1",
  //   "origin_jti": "2c335d24-eeb7-48e4-9ace-26eb863681c0",
  //   "event_id": "dc59939a-2747-43ca-b568-b02e14c0165b",
  //   "token_use": "access",
  //   "scope": "aws.cognito.signin.user.admin",
  //   "auth_time": 1733291810,
  //   "exp": 1733295410,
  //   "iat": 1733291810,
  //   "jti": "8873d56e-17db-49b6-afd1-4de7cfaa10f0",
  //   "username": "fahim"
  // }

  try {
    const data = await client.send(params);
    console.log(data);
    res.json(data);
  } catch (error) {
    res.status(400).json(error);
  }
});

app.post("/verify", async (req, res) => {
  const token = req.body["token"];
  try {
    const payload = await verifier.verify(
      token // the JWT as string
    );
    console.log("Token is valid. Payload:", payload);
    res.json(payload);
  } catch {
    console.log("Token not valid!");
    res.status(401).json({ error: "Token not valid!" });
  }
});

// get user info
app.post("/user", async (req, res) => {
  const { token } = req.body;

  const params = new GetUserCommand({
    AccessToken: token,
  });

  try {
    const data = await client.send(params);
    console.log(data);
    res.json(data);
  } catch (error) {
    res.status(400).json(error);
  }
});

// admin
app.post("/admin/signin", async (req, res) => {
  const { username, password } = req.body;

  const params = new AdminInitiateAuthCommand({
    AuthFlow: AuthFlowType.ADMIN_USER_PASSWORD_AUTH,
    ClientId: CLIENT_ID,
    UserPoolId: process.env.AWS_USER_POOL_ID,
    AuthParameters: {
      USERNAME: username,
      PASSWORD: password,
      // SECRET_HASH: getSecretHash(username, CLIENT_ID, CLIENT_SECRET),
    },
  });

  try {
    const data = await client.send(params);
    console.log(data);
    res.json(data);
  } catch (error) {
    res.status(400).json(error);
  }
});

app.listen(port, () => {
  console.log("server is running 3000");
});
