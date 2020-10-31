import {
    PublicKeyCredentialCreationOptionsJSON,
    PublicKeyCredentialRequestOptionsJSON,
    PublicKeyCredentialDescriptorJSON,
    AttestationCredential,
    AttestationCredentialJSON,
    AssertionCredential,
    AssertionCredentialJSON
} from '@simplewebauthn/typescript-types'

function base64URLStringToBuffer(base64URLString: string): ArrayBuffer {
    const base64 = base64URLString.replace(/-/g, '+').replace(/_/g, '/')
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0))
}

function bufferToBase64URLString(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer)

    // @ts-ignore
    const base64String = btoa(String.fromCharCode(...bytes))
    return base64String
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '')
}

function toUint8Array(value: string): Uint8Array {
    const utf8Encoder = new TextEncoder()
    return utf8Encoder.encode(value)
}

function toPublicKeyCredentialDescriptor(descriptor: PublicKeyCredentialDescriptorJSON): PublicKeyCredentialDescriptor {
    const {id} = descriptor
    return {
        ...descriptor,
        id: base64URLStringToBuffer(id),
    }
}

async function startAttestation(attestationOptions: string): Promise<string> {
    const creationOptionsJSON: PublicKeyCredentialCreationOptionsJSON = JSON.parse(attestationOptions)

    const publicKey: PublicKeyCredentialCreationOptions = {
        ...creationOptionsJSON,
        challenge: base64URLStringToBuffer(creationOptionsJSON.challenge),
        user: {
            ...creationOptionsJSON.user,
            id: toUint8Array(creationOptionsJSON.user.id),
        },
        excludeCredentials: creationOptionsJSON.excludeCredentials.map(toPublicKeyCredentialDescriptor),
    }

    const credential = (await navigator.credentials.create({publicKey})) as AttestationCredential
    if (!credential) {
        throw new Error('Attestation was not completed')
    }

    const {id, rawId, response, type} = credential

    // Convert values to base64 to make it easier to send back to the server
    const credentialJSON: AttestationCredentialJSON = {
        id,
        rawId: bufferToBase64URLString(rawId),
        response: {
            attestationObject: bufferToBase64URLString(response.attestationObject),
            clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
        },
        type
    }

    if (typeof response.getTransports === 'function') {
        credentialJSON.transports = response.getTransports()
    }

    return JSON.stringify(credentialJSON)
}

async function startAssertion(assertionOptions: string): Promise<string> {
    const assertionOptionsJSON: PublicKeyCredentialRequestOptionsJSON = JSON.parse(assertionOptions)

    const publicKey: PublicKeyCredentialRequestOptions = {
        ...assertionOptionsJSON,
        challenge: base64URLStringToBuffer(assertionOptionsJSON.challenge),
        allowCredentials: assertionOptionsJSON.allowCredentials.map(toPublicKeyCredentialDescriptor)
    }

    const credential = (await navigator.credentials.get({publicKey})) as AssertionCredential
    if (!credential) {
        throw new Error('Assertion was not completed')
    }

    const {id, rawId, response, type} = credential

    let userHandle = undefined
    if (response.userHandle) {
        userHandle = bufferToBase64URLString(response.userHandle)
    }

    const assertionJSON: AssertionCredentialJSON = {
        id,
        rawId: bufferToBase64URLString(rawId),
        response: {
            authenticatorData: bufferToBase64URLString(response.authenticatorData),
            clientDataJSON: bufferToBase64URLString(response.clientDataJSON),
            signature: bufferToBase64URLString(response.signature),
            userHandle
        },
        type
    }

    return JSON.stringify(assertionJSON)
}
