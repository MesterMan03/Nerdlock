import cors from "cors";
import { randomUUID } from "crypto";
import express, { Express } from "express";
import { readFileSync } from "fs";
import { createServer as createHttp, Server as HttpServer } from "http";
import { createServer as createHttps, Server as HttpsServer } from "https";
import { Snowflake } from "nodejs-snowflake";
import { join } from "path";
import { fileURLToPath, URL } from "url";
import lockRouter from "./routers/lockRouter.js";
import { ServerConfig } from "./types.js";
import compression from "compression";
import session from "express-session";
import { Fido2Lib } from "fido2-lib";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

export class NerdServer {
    app: Express;
    server: HttpsServer | HttpServer;
    config: ServerConfig;
    snowflake: Snowflake;
    f2l: Fido2Lib;

    constructor(config: ServerConfig) {
        this.snowflake = new Snowflake({
            custom_epoch: 1640995200,
            instance_id: 69
        })
        this.config = config;

        this.f2l = new Fido2Lib({
            rpId: new URL(config.origin).hostname,
            rpName: "Nerdlock",
            challengeSize: 128,
            authenticatorAttachment: "cross-platform",
            authenticatorUserVerification: "discouraged",
            attestation: "direct",
            cryptoParams: [-7]
        });

        this.start();
    }

    async start() {
        // set up express
        this.app = express();
        this.server = this.config.useHttps ? createHttps({
            cert: readFileSync(this.config.sslCert),
            key: readFileSync(this.config.sslKey),
            ca: this.config.sslChain ? readFileSync(this.config.sslChain) : undefined,
            passphrase: "12345678" // passphrase for my testing localhost cert
        }, this.app) : createHttp(this.app);

        this.setupExpress();
    }

    setupExpress() {
        this.server.listen(this.config.port, () => {
            console.log(`[Nerdlock] Server successfully started on port ${this.config.port}`);
        });

        this.app.use(cors({ origin: "*", credentials: true }));
        this.app.use(express.json({ limit: 15_000_000 }));
        this.app.use(express.urlencoded({ limit: 15_000_000, extended: true }));
        this.app.use(compression({
            filter: (req, res) => {
                if (req.accepts("text/event-stream")) return false;
                return true;
            }
        }));
        this.app.set("trust proxy", 1);
        this.app.use(session({
            secret: this.config.dbSecret,
            cookie: {
                secure: true,
                httpOnly: true,
                signed: true,
                sameSite: "strict"
            },
            name: "subscribeToMester:)",
            resave: false,
            saveUninitialized: false
        }))

        // apply a random uuid to each request
        this.app.use((req, res, next) => {
            req.reqId = randomUUID();
            next();
        });

        this.app.use(express.static(join(__dirname, "public"), { index: ["nerdlock.html", "index.html"] }));

        this.app.use("/_nerdlock", lockRouter);

        // set up 404
        this.app.use((req, res, next) => {
            res.status(404);

            res.json({ error: "You were looking so hard, you accidentally found nothing." });
        })
    }
}