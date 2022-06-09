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
    var credential = null;

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
    fetch('/user/' + state.user.name + '/exists')
        .then(response => response.json())
        .then(data => console.log(data));
    // .done(function (response) {
    //         console.log(response);
    //     }).then(function () {
            
    //         var user_verification = $('#select-verification').find(':selected').val();            
    //         var txAuthSimple_extension = $('#extension-input').val();

    //         $.get('/assertion/' + state.user.name, {
    //             userVer: user_verification,
    //             txAuthExtension: txAuthSimple_extension
    //         }, null, 'json')
    //             .done(function (makeAssertionOptions) {
    //                 console.log("Assertion Options:");
    //                 console.log(makeAssertionOptions);
    //                 makeAssertionOptions.publicKey.challenge = bufferDecode(makeAssertionOptions.publicKey.challenge);
    //                 makeAssertionOptions.publicKey.allowCredentials.forEach(function (listItem) {
    //                     listItem.id = bufferDecode(listItem.id)
    //                 });
    //                 console.log(makeAssertionOptions);
    //                 navigator.credentials.get({
    //                         publicKey: makeAssertionOptions.publicKey
    //                     })
    //                     .then(function (credential) {
    //                         console.log(credential);
    //                         verifyAssertion(credential);
    //                     }).catch(function (err) {
    //                         console.log(err.name);
    //                         showErrorAlert(err.message);
    //                     });
    //             });
    //     })
    //     .catch(function (error) {
    //         if (!error.exists) {
    //             showErrorAlert("User not found, try registering one first!");
    //         }
    //         return;
    //     });
}


// function getAssertion() {
//     if (!PublicKeyCredential.isConditionalMediationAvailable ||
//         !PublicKeyCredential.isConditionalMediationAvailable()) {
//         // Browser doesn't support AutoFill-assisted requests.
//         alert("Unsupported")
//         return;
//     }

//     const options = {
//         "publicKey": {
//             challenge: "… // Fetched from server"
//         },
//         mediation: "conditional"
//     };

//     navigator.credentials.get(options)
//         .then(assertion => { 
//             // Pass the assertion to your server.
//         });
// }

// const publicKeyCredentialCreationOptions = {
//     challenge: Uint8Array.from(
//         randomStringFromServer, c => c.charCodeAt(0)),
//     rp: {
//         name: "Vapor",
//         id: "vapor.codes",
//     },
//     user: {
//         id: Uint8Array.from(
//             "UZSL85T9AFC", c => c.charCodeAt(0)),
//         name: "lee@webauthn.guide",
//         displayName: "Lee",
//     },
//     pubKeyCredParams: [{alg: -7, type: "public-key"}],
//     authenticatorSelection: {
//         authenticatorAttachment: "cross-platform",
//     },
//     timeout: 60000,
//     attestation: "direct"
// };

function bufferDecode(value) {
    return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

function bufferEncode(value) {
    return base64js.fromByteArray(value)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}