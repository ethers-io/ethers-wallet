'use strict';

import * as secp from 'noble-secp256k1';

import { getAddress } from './address';

import { arrayify, hexlify, hexZeroPad, splitSignature, joinSignature } from './bytes';
import { hashMessage } from './hash';
import { keccak256 } from './keccak256';
import { defineReadOnly } from './properties';

import * as errors from '../errors';

///////////////////////////////
// Imported Types

import { Arrayish, Signature } from './bytes';

///////////////////////////////

// let _curve: EC = null;
function numberFromByteArray(bytes: Uint8Array): bigint {
    let value = 0n;
    for (let i = bytes.length - 1, j = 0; i >= 0; i--, j++) {
        value += (BigInt(bytes[i]) & 255n) << (8n * BigInt(j));
    }
    return value;
}

export class KeyPair {

    readonly privateKey: string;

    readonly publicKey: string;
    readonly compressedPublicKey: string;

    readonly publicKeyBytes: Uint8Array;

    constructor(privateKey: Arrayish | string) {
        const priv = arrayify(privateKey);
        const privn = numberFromByteArray(priv);
        const point = secp.Point.fromPrivateKey(privn);
        defineReadOnly(this, 'privateKey', hexlify(priv));
        defineReadOnly(this, 'publicKey', '0x' + point.toHex(false));
        defineReadOnly(this, 'compressedPublicKey', '0x' + point.toHex(true));
        defineReadOnly(this, 'publicKeyBytes', point.toRawBytes());
    }

    sign(digest: Arrayish | string): Signature {
        const hash = arrayify(digest);
        const priv = arrayify(this.privateKey);
        const [signature, rec] = secp.sign(hash, priv, {canonical: true, recovered: true})
        const recovery = Number(rec);
        const {r, s} = secp.SignResult.fromHex(signature);
        return {
            recoveryParam: recovery,
            r: hexZeroPad('0x' + r.toString(16), 32),
            s: hexZeroPad('0x' + s.toString(16), 32),
            v: 27 + recovery
        }

    }

    computeSharedSecret(otherKey: Arrayish | string): string {
        const priv = arrayify(this.privateKey);
        const pub = arrayify(computePublicKey(otherKey));
        const shared = secp.getSharedSecret(priv, pub);
        return hexZeroPad('0x' + hexlify(shared), 32);
    }

    _addPoint(other: Arrayish | string): string {
        let p0 = secp.Point.fromHex(arrayify(this.publicKey));
        let p1 = secp.Point.fromHex(arrayify(other));
        return "0x" + p0.add(p1).toHex(true);
    }
}

export function computePublicKey(key: Arrayish | string, compressed?: boolean): string {

    let bytes = arrayify(key);

    if (bytes.length === 32) {
        let keyPair: KeyPair = new KeyPair(bytes);
        if (compressed) {
            return keyPair.compressedPublicKey;
        }
        return keyPair.publicKey;

    } else if (bytes.length === 33) {
        if (compressed) { return hexlify(bytes); }
        return '0x' + secp.Point.fromHex(bytes).toHex();
    } else if (bytes.length === 65) {
        if (!compressed) { return hexlify(bytes); }
        return '0x' + secp.Point.fromHex(bytes).toHex(true);
    }

    errors.throwError('invalid public or private key', errors.INVALID_ARGUMENT, { arg: 'key', value: '[REDACTED]' });
    return null;
}

export function computeAddress(key: Arrayish | string): string {
    // Strip off the leading "0x04"
    let publicKey = '0x' + computePublicKey(key).slice(4);
    return getAddress('0x' + keccak256(publicKey).substring(26));
}

export function recoverPublicKey(digest: Arrayish | string, signature: Signature | string): string {
    let sig = splitSignature(signature);
    let rs = { r: arrayify(sig.r), s: arrayify(sig.s) };
    const hash = arrayify(digest);
    const hexSig = hexlify(joinSignature(sig));
    return '0x' + hexlify(secp.recoverPublicKey(hash, hexSig, sig.recoveryParam));
}

export function recoverAddress(digest: Arrayish | string, signature: Signature | string): string {
    return computeAddress(recoverPublicKey(arrayify(digest), signature));
}

export function verifyMessage(message: Arrayish | string, signature: Signature | string): string {
    return recoverAddress(hashMessage(message), signature);
}
