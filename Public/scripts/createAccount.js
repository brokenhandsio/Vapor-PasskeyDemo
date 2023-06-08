const createAccountForm = document.getElementById("createAccountForm");
const createAccountError = document.getElementById("createAccountError");

createAccountForm.addEventListener("submit", async function(event) {
    event.preventDefault();
    hideCreateAccountError();

    const username = document.getElementById("username").value;

    try {
        const credentialCreationOptions = await fetchCredentialCreationOptions(username);
        const registrationCredential = await navigator.credentials.create({ publicKey: credentialCreationOptions });
        await registerNewCredential(registrationCredential);
    } catch (error) {
        console.log(error);
        return;
    }
    location.href = "/private";
});


async function fetchCredentialCreationOptions(username) {
    const makeCredentialsResponse = await fetch('/signup?username=' + username);
    if (makeCredentialsResponse.status == 409) {
        showCreateAccountError("Username is already taken");
        throw new Error("Username is already taken");
    } else if (!makeCredentialsResponse.status == 200) {
        showCreateAccountError("Something went wrong (" + makeCredentialsResponse.status + ")");
        throw new Error("Signup request failed");
    }

    let credentialCreationOptions = await makeCredentialsResponse.json();
    credentialCreationOptions.challenge = bufferDecode(credentialCreationOptions.challenge);
    credentialCreationOptions.user.id = bufferDecode(credentialCreationOptions.user.id);

    return credentialCreationOptions;
}

async function registerNewCredential(newCredential) {
    // Move data into Arrays incase it is super long
    const attestationObject = new Uint8Array(newCredential.response.attestationObject);
    const clientDataJSON = new Uint8Array(newCredential.response.clientDataJSON);
    const rawId = new Uint8Array(newCredential.rawId);

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

    if (registerResponse.status != 200) {
        showCreateAccountError("Something went wrong (" + makeCredentialsResponse.status + ")");
        throw new Error("makeCredential request failed");
    }
}

function showCreateAccountError(message) {
    createAccountError.innerHTML = message;
    createAccountError.classList.remove("hidden");
}

function hideCreateAccountError() {
    createAccountError.classList.add("hidden");
}