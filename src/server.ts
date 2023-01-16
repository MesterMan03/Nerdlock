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
import expressCSP from "express-csp-header";

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
        this.app.use(cors({ origin: "*", credentials: true }));

        this.app.use(express.json({ limit: 15_000_000 }));
        this.app.use(express.urlencoded({ limit: 15_000_000, extended: true }));

        this.app.use(compression({
            filter: (req, res) => req.baseUrl !== "/_nerdlock/sse"
        }));

        this.app.use(expressCSP.expressCspHeader({
            directives: {
                "default-src": [expressCSP.SELF],
                "script-src": [expressCSP.SELF],
                "style-src": [expressCSP.SELF, expressCSP.INLINE],
                "img-src": [expressCSP.SELF, expressCSP.DATA],
                "media-src": [expressCSP.SELF, expressCSP.DATA],
                "connect-src": ["*"]
            }
        }))

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

        this.app.use((req, res, next) => {
            // apply a random uuid to each request
            req.reqId = randomUUID();
            next();
        });

        this.app.use(express.static(join(__dirname, "public"), { index: ["nerdlock.html", "index.html"] }));

        this.app.use("/_nerdlock", lockRouter);

        // set up 404
        this.app.use((req, res, next) => {
            res.status(404);

            res.json({ error: "You were looking so hard, you accidentally found nothing." });
        });

        this.server.listen(this.config.port, () => {
            console.log(`[Nerdlock] Server successfully started on port ${this.config.port}`);
        });
    }
}