const signInForm = document.getElementById("signInForm");
const authenticateError = document.getElementById("authenticateError");

signInForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    try {
        const publicKeyCredentialRequestOptions = await fetchCredentialRequestOptions();
        const credential = await navigator.credentials.get({
            publicKey: publicKeyCredentialRequestOptions,
        });

        await signIn(credential);
    } catch (error) {
        console.log(error);
        return;
    }

    location.href = "/private";
});

async function fetchCredentialRequestOptions() {
    const authenticateResponse = await fetch("/authenticate");
    const publicKeyCredentialRequestOptions = await authenticateResponse.json();

    if (publicKeyCredentialRequestOptions.allowCredentials) {
        publicKeyCredentialRequestOptions.allowCredentials = publicKeyCredentialRequestOptions.allowCredentials.map(
            (allowedCredential) => {
                return {
                    id: bufferDecode(allowedCredential.id),
                    type: allowedCredential.type,
                    transports: allowedCredential.transports,
                };
            }
        );
    }

    publicKeyCredentialRequestOptions.challenge = bufferDecode(publicKeyCredentialRequestOptions.challenge);

    return publicKeyCredentialRequestOptions;
}

async function signIn(credential) {
    // Move data into Arrays incase it is super long
    let authData = new Uint8Array(credential.response.authenticatorData);
    let clientDataJSON = new Uint8Array(credential.response.clientDataJSON);
    let rawId = new Uint8Array(credential.rawId);
    let sig = new Uint8Array(credential.response.signature);
    let userHandle = new Uint8Array(credential.response.userHandle);

    const authenticateResponse = await fetch("/authenticate", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            id: credential.id,
            rawId: bufferEncode(rawId),
            type: credential.type,
            response: {
                authenticatorData: bufferEncode(authData),
                clientDataJSON: bufferEncode(clientDataJSON),
                signature: bufferEncode(sig),
                userHandle: bufferEncode(userHandle),
            },
        }),
    });

    if (authenticateResponse.status == 401) {
        showAuthenticateError("Unauthorized");
        throw new Error("Unauthorized");
    } else if (!authenticateResponse.status == 200) {
        showAuthenticateError("Something went wrong (" + authenticateResponse.status + ")");
        throw new Error("Authentication request failed");
    }
}

function showAuthenticateError(message) {
    authenticateError.innerHTML = message;
    authenticateError.classList.remove("hidden");
}

function hideAuthenticateError() {
    authenticateError.classList.add("hidden");
}
