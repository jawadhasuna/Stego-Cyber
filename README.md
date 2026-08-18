# Vault

**Live app:** https://vaultstego.vercel.app

Vault is a browser-based steganography tool that hides an AES-encrypted message inside the pixels of an image. Encryption uses the Web Crypto API with PBKDF2 key derivation and AES-GCM, and the message is embedded via least-significant-bit manipulation on a canvas — everything runs entirely client-side, so no image or password ever leaves your device.
## Try it out

A sample encoded image (`vault-encoded.png`) is included in this repo with a hidden message inside it. To reveal it: download the file, open the live app, go to the **Recover** tab, upload the image, enter the cipher key `alpha123`, and click **Execute Recover** — the hidden message will appear in the payload box.
