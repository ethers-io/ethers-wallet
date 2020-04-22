"use strict";

import net from 'net';

import { JsonRpcProvider } from './json-rpc-provider';

import { defineReadOnly } from '../utils/properties';

// Imported Types
import { Networkish } from '../utils/networks';

import * as errors from '../errors';


export class IpcProvider extends JsonRpcProvider {
    readonly path: string;

    constructor(path: string, network?: Networkish) {
        if (path == null) {
            errors.throwError('missing path', errors.MISSING_ARGUMENT, {
                argument: 'path'
            });
        }

        super('ipc://' + path, network);
        errors.checkNew(this, IpcProvider);

        defineReadOnly(this, 'path', path);
    }

    // @TODO: Create a connection to the IPC path and use filters instead of polling for block

    send(method: string, params: any): Promise<any> {
        // This method is very simple right now. We create a new socket
        // connection each time, which may be slower, but the main
        // advantage we are aiming for now is security. This simplifies
        // multiplexing requests (since we do not need to multiplex).

        let payload = JSON.stringify({
            method: method,
            params: params,
            id: 42,
            jsonrpc: "2.0"
        });

        return new Promise((resolve, reject) => {
            let response = Buffer.alloc(0);

            let stream = net.connect(this.path);

            stream.setTimeout(5e3, () => stream.destroy());
            stream.once('connect', () => stream.setTimeout(0));

            stream.on('data', (data) => {
                response = Buffer.concat([ response, data ]);
            });

            stream.on("end", () => {
                try {
                    const payload = JSON.parse(response.toString('utf8'));
                    if (payload.error) {
                        const error: any = new Error(payload.error.message);
                        error.code = payload.error.code;
                        error.data = payload.error.data;
                        reject(error);
                    } else {
                        resolve(payload.result);
                    }
                    stream.destroy();
                } catch (error) {
                    reject(error);
                    stream.destroy();
                }
            });

            stream.on('error', (error) => {
                reject(error);
                stream.destroy();
            });

            stream.write(payload);
            stream.end();
        });
    }
}
