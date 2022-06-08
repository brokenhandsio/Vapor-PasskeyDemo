function signIn() {
    if (!PublicKeyCredential.isConditionalMediationAvailable ||
        !PublicKeyCredential.isConditionalMediationAvailable()) {
        // Browser doesn't support AutoFill-assisted requests.
        alert("Unsupported")
        return;
    }

    const options = {
        "publicKey": {
            challenge: "… // Fetched from server"
        },
        mediation: "conditional"
    };

    navigator.credentials.get(options)
        .then(assertion => { 
            // Pass the assertion to your server.
        });
}