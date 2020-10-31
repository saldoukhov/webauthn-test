import {
    generateAssertionOptions,
    generateAttestationOptions, verifyAssertionResponse,
    verifyAttestationResponse,
} from '@simplewebauthn/server';
import {
    AttestationCredentialJSON,
    AssertionCredentialJSON,
    PublicKeyCredentialDescriptorJSON
} from '@simplewebauthn/typescript-types';
import {connect} from 'puppeteer'
import {transpile} from 'typescript'
import * as fs from 'fs'
import {spawn} from 'child_process'

// Human-readable title for your website
const rpName = 'WebAuthn Test';
// A unique identifier for your website
const rpID = 'localhost';
// The URL at which attestations and assertions should occur
const origin = `http://${rpID}`;

const excludedDevices: PublicKeyCredentialDescriptorJSON[] = []

async function executeApp(command: string, args: string[]): Promise<string> {
    return new Promise(((resolve) => {
        const chromeOutput = spawn(command, args)
        chromeOutput.stderr.on('data', (data: Buffer) => {
            resolve(data.toString())
        })
    }))
}

const test = async () => {

    // Prepare browser
    const chromeCommand = '/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome'
    const chromeArgs = [
        '--remote-debugging-port=9222',
        '--no-first-run',
        '--no-default-browser-check',
        '--user-data-dir=./data_dir'
    ]
    const chromeOutput = await executeApp(chromeCommand, chromeArgs)
    const chromeUrl = chromeOutput.match(/ws.*/)[0]
    const browser = await connect({
        browserWSEndpoint: chromeUrl
    })
    const pages = await browser.pages()
    const page = pages[0]
    await page.goto('http://localhost')
    await page.evaluate(() => {
        document.body.innerHTML = '<br><br><br><H1>ATTESTATION</H1>'
    })
    page.on('console', msg => {
        const text = msg.text()
        if (!text.endsWith('404 (Not Found)')) {
            console.log(msg.text());
        }
    });
    await page.addScriptTag({content: transpile(fs.readFileSync('./browser.ts').toString())})


    // WebAuthn attestation
    console.log("PERFORMING ATTESTATION")
    const attestationOptions = generateAttestationOptions({
        rpName,
        rpID,
        userID: '12345',
        userName: 'bob',
        // Don't prompt users for additional information about the authenticator
        // (Recommended for smoother UX)
        attestationType: 'indirect',
        // Prevent users from re-registering existing authenticators
        excludeCredentials: excludedDevices,
    });
    console.log('\nattestation options:')
    console.log(attestationOptions)

    const attestationResponse = await page.evaluate((input) => {
        // @ts-ignore
        return window.startAttestation(input)
    }, JSON.stringify(attestationOptions))
    const attestationCredentialJSON: AttestationCredentialJSON = JSON.parse(attestationResponse)
    console.log('\nattestation response:')
    console.log(attestationCredentialJSON)

    const attestationVerification = await verifyAttestationResponse({
        credential: attestationCredentialJSON,
        expectedChallenge: attestationOptions.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID
    })
    console.log('\nattestation verification result');
    console.log(attestationVerification)

    // WebAuthn assertion
    console.log("PERFORMING ASSERTION")
    await page.evaluate(() => {
        document.body.innerHTML = '<br><br><br><H1>ASSERTION</H1>'
    })

    const assertionOptions = generateAssertionOptions({
        // Require users to use a previously-registered authenticator
        allowCredentials: [{
            id: attestationVerification.authenticatorInfo.base64CredentialID,
            type: 'public-key',
            // Optional
            transports: ['usb'],
        }],
        userVerification: 'preferred',
    });
    console.log(assertionOptions)

    const assertionResponse = await page.evaluate((input) => {
        // @ts-ignore
        return window.startAssertion(input)
    }, JSON.stringify(assertionOptions))
    const assertionCredentialJSON: AssertionCredentialJSON = JSON.parse(assertionResponse)
    console.log('\nassertion response:')
    console.log(assertionCredentialJSON)

    const assertionVerification = await verifyAssertionResponse({
        credential: assertionCredentialJSON,
        expectedChallenge: assertionOptions.challenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        authenticator: {
            counter: attestationVerification.authenticatorInfo.counter,
            credentialID: attestationVerification.authenticatorInfo.base64CredentialID,
            publicKey: attestationVerification.authenticatorInfo.base64PublicKey
        }
    })
    console.log('\nassertion verification result');
    console.log(assertionVerification)

    await browser.close()
};

test().finally()

