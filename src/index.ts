import * as TOML from "@ltd/j-toml";
import { readFile } from "fs/promises";
import mongoose from "mongoose";
import Mongoose from "mongoose";
import { NerdServer } from "./server.js";
import { ServerConfig } from "./types.js";
import { validateServerConfig } from "./utils.js";

const NerdVersion = "b1.0.3";

if (process.argv.length <= 2) {
    console.log("No arguments were supplied! Exiting...");
    process.exit(1);
}

const verb = process.argv[2];

let nerdServer: NerdServer;

switch (verb) {
    case "start": {
        if (!process.argv[3]) {
            console.log("Missing config file. Exiting...");
            process.exit(1);
        }

        const confFilePath = process.argv[3];

        // read config file
        const confFile = await readFile(confFilePath)
            .then((b) => { return b.toString(); })
            .catch(() => {
                console.log("Config file was not found! Exiting...");
                process.exit(1);
            })
        const configTable = TOML.parse(confFile);

        const config: ServerConfig = {
            dbSecret: configTable["db_secret"].toString(),
            dbUrl: configTable["db_url"].toString(),
            dbKey: configTable["db_key"]?.toString(),
            port: Number.parseInt(configTable["port"].toString()),
            sslCert: configTable["ssl_cert"].toString(),
            sslKey: configTable["ssl_key"].toString(),
            sslChain: configTable["ssl_chain"]?.toString(),
            allowReg: configTable["allow_registration"].toString() === "true",
            useHttps: configTable["use_https"].toString() === "true",
            origin: configTable["origin"].toString()
        }

        // validate config
        let validateResult: string;
        if (validateResult = validateServerConfig(config)) {
            throw new Error(`Invalid config: ${validateResult}`);
        }

        // connect to mongo
        mongoose.set("strictQuery", false);
        const options: mongoose.ConnectOptions = Object.assign({}, {
            retryWrites: true
        }, config.dbKey ? { sslCert: config.dbKey, sslKey: config.dbKey } : null);
        await Mongoose.connect(config.dbUrl, options).catch((error) => {
            console.error(`Couldn't connect to MongoDB: ${error}`);
            process.exit(1);
        });

        nerdServer = new NerdServer(config);
        break;
    }
    case "help":
    default: {
        console.log("Help menu")
    }
}

// this is not nice, but whatever
process.on("uncaughtException", (error) => {
    console.error(`Uncaught error: ${error.stack}`);
})

export { nerdServer, NerdVersion };