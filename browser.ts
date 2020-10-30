import {
    PublicKeyCredentialCreationOptionsJSON,
    PublicKeyCredentialDescriptorJSON,
    AttestationCredential
} from '@simplewebauthn/typescript-types';

function base64URLStringToBuffer(base64URLString: string): ArrayBuffer {
    // Convert from Base64URL to Base64
    const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/');
    /**
     * Pad with '=' until it's a multiple of four
     * (4 - (85 % 4 = 1) = 3) % 4 = 3 padding
     * (4 - (86 % 4 = 2) = 2) % 4 = 2 padding
     * (4 - (87 % 4 = 3) = 1) % 4 = 1 padding
     * (4 - (88 % 4 = 0) = 4) % 4 = 0 padding
     */
    const padLength = (4 - (base64.length % 4)) % 4;
    const padded = base64.padEnd(base64.length + padLength, '=');

    // Convert to a binary string
    const binary = atob(padded);

    // Convert binary string to buffer
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return buffer;
}

function toUint8Array(value: string): Uint8Array {
    const utf8Encoder = new TextEncoder();
    return utf8Encoder.encode(value);
}

function toPublicKeyCredentialDescriptor(descriptor: PublicKeyCredentialDescriptorJSON): PublicKeyCredentialDescriptor {
    const {id} = descriptor;
    return {
        ...descriptor,
        id: base64URLStringToBuffer(id),
    };
}

async function startAttestation(creationOptions: string): Promise<string> {
    const creationOptionsJSON: PublicKeyCredentialCreationOptionsJSON = JSON.parse(creationOptions)

    const publicKey: PublicKeyCredentialCreationOptions = {
        ...creationOptionsJSON,
        challenge: base64URLStringToBuffer(creationOptionsJSON.challenge),
        user: {
            ...creationOptionsJSON.user,
            id: toUint8Array(creationOptionsJSON.user.id),
        },
        excludeCredentials: creationOptionsJSON.excludeCredentials.map(toPublicKeyCredentialDescriptor),
    };

    // console.log(navigator.credentials ? 'yes' : 'no')

    const credential = (await navigator.credentials.create({publicKey})) as AttestationCredential;
    console.log(credential)

    return "Ok"
}
