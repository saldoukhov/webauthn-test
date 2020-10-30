import {
    generateAttestationOptions,
    verifyAttestationResponse,
} from '@simplewebauthn/server';
import {PublicKeyCredentialDescriptorJSON} from '@simplewebauthn/typescript-types';
import {launch, connect} from 'puppeteer'
import {transpile} from 'typescript'
import * as fs from 'fs'
import { exec, spawn, spawnSync } from 'child_process'

type UserModel = {
    id: string;
    username: string;
    currentChallenge?: string;
};

// It is strongly advised that authenticators get their own DB
// table, ideally with a foreign key to a specific UserModel
type Authenticator = {
    credentialID: string;
    publicKey: string;
    counter: number;
    // ['usb' | 'ble' | 'nfc' | 'internal']
    transports?: AuthenticatorTransport[];
};

// Human-readable title for your website
const rpName = 'WebAuthn Test';
// A unique identifier for your website
const rpID = 'localhost';
// The URL at which attestations and assertions should occur
const origin = `https://${rpID}`;

const user: UserModel = {
    id: 'bob_id',
    username: 'bob',
}

const excludedDevices: PublicKeyCredentialDescriptorJSON[] = []

async function executeApp(command: string, args: string[]): Promise<string> {
    return new Promise(((resolve, reject) => {
        const chromeOutput = spawn(command, args)
        chromeOutput.stderr.on('data', (data: Buffer) => {
            resolve(data.toString())
        })
    }))
}


const test = async () => {

    const chromeCommand = '/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome'
    const chromeArgs = [
        '--remote-debugging-port=9222',
        '--no-first-run',
        '--no-default-browser-check',
        '--user-data-dir=./data_dir'
    ]

    const chromeOutput = await executeApp(chromeCommand, chromeArgs)
    const chromeUrl = chromeOutput.match(/ws.*/)[0]

    const options = generateAttestationOptions({
        rpName,
        rpID,
        userID: user.id,
        userName: user.username,
        // Don't prompt users for additional information about the authenticator
        // (Recommended for smoother UX)
        attestationType: 'indirect',
        // Prevent users from re-registering existing authenticators
        excludeCredentials: excludedDevices,
    });

    const browser = await connect({
        browserWSEndpoint: chromeUrl
    })

    const pages = await browser.pages()
    const page = pages[0]
    await page.goto('http://localhost')

    page.on('console', msg => {
        console.log(msg['_text']);
    });

    await page.addScriptTag({content: transpile(fs.readFileSync('./browser.ts').toString())})

    const token = await page.evaluate((input) => {
        // @ts-ignore
        return window.startAttestation(input)
    }, JSON.stringify(options))
    console.log(token)
    await browser.close()
};

test().finally()

