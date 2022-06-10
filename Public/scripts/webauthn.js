function hideErrorAlert() {
    document.getElementById("alert").classList.add("d-none");
}

function showErrorAlert(msg) {
    document.getElementById("alert-message").innerHTML = msg;
    document.getElementById("alert").classList.remove("d-none");
}

var state = {
    createResponse: null,
    publicKeyCredential: null,
    credential: null,
    user: {
        name: "testuser@example.com",
        displayName: "testuser",
    },
}

function setUser() {
    username = document.getElementById("username").value;
    state.user.name = username.toLowerCase().replace(/\s/g, '');
    state.user.displayName = username.toLowerCase();
}

async function makeCredential() {
    hideErrorAlert();
    console.log("Fetching options for new credential");
    if (document.getElementById("username").value === "") {
        showErrorAlert("Please enter a username");
        return;
    }
    setUser();

    const makeCredentialsResponse = await fetch('/makeCredential?username=' + state.user.name);
    console.log(makeCredentialsResponse);
    const makeCredentialsResponseJson = await makeCredentialsResponse.json();
    console.log(makeCredentialsResponseJson);

    const challenge = bufferDecode(makeCredentialsResponseJson.challenge);
    const userId = bufferDecode(makeCredentialsResponseJson.userID)

    var publicKey = {
        challenge: challenge,
        rp: {
            name: "Vapor Demo"
        },
        user: {
            id: userId,
            name: state.user.name,
            displayName: state.user.displayName,
        },
        pubKeyCredParams: [
            {
                type: "public-key",
                alg: -7
            }
        ],
        authenticatorSelection: {
            userVerification: "preferred"
        }
    }

    try {
        const newCredential = await navigator.credentials.create({ publicKey });
        console.log(newCredential);
        state.createResponse = newCredential;
        registerNewCredential(newCredential);
    } catch(error) {
        console.log(error);
        showErrorAlert(error.message);
    }
}

// This should be used to verify the auth data with the server
async function registerNewCredential(newCredential) {
    // Move data into Arrays incase it is super long
    let attestationObject = new Uint8Array(newCredential.response.attestationObject);
    let clientDataJSON = new Uint8Array(newCredential.response.clientDataJSON);
    let rawId = new Uint8Array(newCredential.rawId);

    console.log("Registering new credential");

    try {
        const registerResponse = await fetch('/makeCredential', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                id: newCredential.id,
                rawId: bufferEncode(rawId),
                type: newCredential.type,
                response: {
                    attestationObject: bufferEncode(attestationObject),
                    clientDataJSON: bufferEncode(clientDataJSON),
                },
            })
        });

        if (!registerResponse.ok) {
            throw new Error(`HTTP error: ${registerResponse.status}`);
        }
        window.location = '/private';
    } catch (error) {
        console.log(error);
        showErrorAlert(error.message);
    }
}

async function getAssertion() {
    hideErrorAlert();
    if (document.getElementById("username").value === "") {
        showErrorAlert("Please enter a username");
        return;
    }
    setUser();

    try {
        const authenticateResponse = await fetch('/authenticate?username=' + state.user.name);
        console.log(authenticateResponse);

        if (!authenticateResponse.ok) {
            throw new Error(`HTTP error: ${authenticateResponse.status}`);
        }
        
        const authenticateJson = await authenticateResponse.json();
        console.log(authenticateJson);

        var allowedCredentials = [];

        authenticateJson.credentials.forEach(credential => {
            const credentialInfo = {
                id: bufferDecode(credential.id),
                type: 'public-key',
            }
            allowedCredentials.push(credentialInfo);
        });

        const publicKeyCredentialRequestOptions = {
            challenge: bufferDecode(authenticateJson.challenge),
            // allowCredentials: allowedCredentials,
        }
        const credential = await navigator.credentials.get({ publicKey: publicKeyCredentialRequestOptions });
        console.log(credential);
        verifyAssertion(credential);
    } catch(error) {
        console.log(error);
        showErrorAlert(error.message);
    }
}

async function verifyAssertion(assertedCredential) {
    // Move data into Arrays incase it is super long
    console.log('calling verify')
    let authData = new Uint8Array(assertedCredential.response.authenticatorData);
    let clientDataJSON = new Uint8Array(assertedCredential.response.clientDataJSON);
    let rawId = new Uint8Array(assertedCredential.rawId);
    let sig = new Uint8Array(assertedCredential.response.signature);
    let userHandle = new Uint8Array(assertedCredential.response.userHandle);

    const authenticateResponse = await fetch('/authenticate', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            id: assertedCredential.id,
            rawId: bufferEncode(rawId),
            type: assertedCredential.type,
            response: {
                authenticatorData: bufferEncode(authData),
                clientDataJSON: bufferEncode(clientDataJSON),
                signature: bufferEncode(sig),
                userHandle: bufferEncode(userHandle),
            },
        })
    });

    if (!authenticateResponse.ok) {
        throw new Error(`HTTP error: ${authenticateResponse.status}`);
    }
    window.location = '/private';
}

function bufferDecode(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

function bufferEncode(value) {
    return base64js.fromByteArray(value)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}