# Vapor Passkey Demo

Proof of concept app for trying to integrate passkeys and WebAuthn into Vapor

![Screenshot of app](/images/demo.png)

## Usage

Clone the project, then in Terminal run

```bash
swift run
```

In your browser go to http://localhost:8080 and follow the steps!

> **Note**: This is proof of concept code to scope out the work to build a Swift Server library for WebAuthn. I do not advise using it in production until it's had some
eyes on it. Many things are unimplemented and untested so be warned! Only tested on macOS 12.4 with Safari 15.5

## Development

If you want to make CSS changes you'll need to download the Tailwind CSS executable and place it in the root of the
project:

```bash
# Example for macOS arm64
curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-macos-arm64
chmod +x tailwindcss-macos-arm64
mv tailwindcss-macos-arm64 tailwindcss
```

Then run the following to generate Tailwind CSS classes and watch for changes:

```bash
./tailwindcss -i Resources/Utils/styles.css -o Public/styles/tailwind.css --watch
```

> Do not edit `Public/styles/tailwind.css` manually as it will be overwritten by the above command!
