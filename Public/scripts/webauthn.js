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
        name: "",
        displayName: "",
    },
}

function setUser() {
    if (document.getElementById("username").value === "") return;
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

    const makeCredentialsResponse = await fetch('/signup?username=' + state.user.name);
    if (makeCredentialsResponse.status !== 200) {
        showErrorAlert("Username is already taken");
        return;
    }

    var credentialCreationOptions = await makeCredentialsResponse.json();
    credentialCreationOptions.challenge = bufferDecode(credentialCreationOptions.challenge);
    credentialCreationOptions.user.id = bufferDecode(credentialCreationOptions.user.id);

    console.log(credentialCreationOptions);

    try {
        let registrationCredential = await navigator.credentials.create({ publicKey: credentialCreationOptions });
        console.log("New credential: " + registrationCredential);
        state.createResponse = registrationCredential;
        await registerNewCredential(registrationCredential);
    } catch(error) {
        const errorMessage = "Creating credential failed: " + error.message;
        console.log(errorMessage);
        await fetch('/makeCredential', { method: 'DELETE' });
        showErrorAlert(errorMessage);
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
    setUser();

    try {
        let query = '';
        if (state.user.name != "") {
            query += '?username=' + state.user.name;
        }
        const authenticateResponse = await fetch('/authenticate' + query);
        console.log(authenticateResponse);

        if (!authenticateResponse.ok) {
            throw new Error(`HTTP error: ${authenticateResponse.status}`);
        }

        const publicKeyCredentialRequestOptions = await authenticateResponse.json();
        console.log(publicKeyCredentialRequestOptions);

        if (publicKeyCredentialRequestOptions.allowCredentials) {
            publicKeyCredentialRequestOptions.allowCredentials = publicKeyCredentialRequestOptions.allowCredentials.map(allowedCredential => {
                return {
                    id: bufferDecode(allowedCredential.id),
                    type: allowedCredential.type,
                    transports: allowedCredential.transports
                };
            });
        }

        publicKeyCredentialRequestOptions.challenge = bufferDecode(publicKeyCredentialRequestOptions.challenge);

        console.log("publicKeyCredentialRequestOptions: ", publicKeyCredentialRequestOptions);

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

    try {
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
    } catch(error) {
        console.log(error);
        showErrorAlert(error.message);
    }
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