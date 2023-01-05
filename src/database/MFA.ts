import mongoose, { Schema, SchemaTypes } from "mongoose";
import { NerdMFA } from "../types.js";

export interface IMFA extends NerdMFA, Document { }

export default mongoose.model("MFA", new Schema<IMFA>({
    userId: {
        type: SchemaTypes.String,
        required: true,
        unique: true
    },
    mfaEnabled: {
        type: SchemaTypes.Boolean,
        default: false
    },
    totp: {
        enabled: {
            type: SchemaTypes.Boolean,
            default: false
        },
        secret: {
            type: SchemaTypes.String,
            default: null
        }
    },
    u2f: {
        enabled: {
            type: SchemaTypes.Boolean,
            default: false
        },
        publicKey: {
            type: SchemaTypes.String,
            default: null
        }
    }
}));