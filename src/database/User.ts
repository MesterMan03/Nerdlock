import mongoose, { Document, SchemaTypes } from "mongoose";
import { NerdUser, } from "../types.js";

export interface INerdUser extends NerdUser, Document { }

export default mongoose.model("User", new mongoose.Schema<INerdUser>({
    username: {
        type: SchemaTypes.String,
        required: true,
        unique: true
    },
    password: {
        type: SchemaTypes.String,
        required: true
    },
    salt: {
        type: SchemaTypes.String,
        required: true
    },
    accessToken: {
        type: SchemaTypes.String,
        required: true
    },
    userId: {
        type: SchemaTypes.String,
        required: true
    },
    masterKey: {
        type: SchemaTypes.String,
        required: true
    },
    public: {
        idenKey: {
            private: {
                type: SchemaTypes.String,
                required: true
            },
            public: {
                type: SchemaTypes.String,
                required: true
            }
        },
        preKey: {
            private: {
                type: SchemaTypes.String,
                required: true
            },
            public: {
                type: SchemaTypes.String,
                required: true
            },
            sign: {
                type: SchemaTypes.String,
                required: true
            }
        },
        oneTimeKeys: {
            type: [{
                id: {
                    type: SchemaTypes.Number,
                    required: true
                },
                public: {
                    type: SchemaTypes.String,
                    required: true
                },
                private: {
                    type: SchemaTypes.String,
                    required: true
                },
            }],
            _id: false,
            required: true
        },
    },
    usedOneTimeKeys: {
        type: [{
            id: {
                type: SchemaTypes.Number,
                required: true
            },
            private: {
                type: SchemaTypes.String,
                required: true
            }
        }],
        _id: false,
        default: []
    },
    secretRequests: {
        type: [{
            from: {
                type: SchemaTypes.String,
                required: true
            },
            identityKey: {
                type: SchemaTypes.String,
                required: true
            },
            ephemeralKey: {
                type: SchemaTypes.String,
                required: true
            },
            otKeyId: {
                type: SchemaTypes.Number,
                required: true
            },
            preMessage: {
                type: SchemaTypes.String,
                required: true
            },
            id: {
                type: SchemaTypes.String,
                required: true
            }
        }],
        _id: false,
        default: []
    },
    secretMessages: {
        type: [{
            from: {
                type: SchemaTypes.String,
                required: true
            },
            message: {
                type: SchemaTypes.String,
                required: true
            }
        }],
        _id: false,
        default: []
    },
    rooms: {
        type: [{
            roomId: {
                type: SchemaTypes.String,
                required: true
            },
            roomSecret: {
                type: SchemaTypes.String,
                required: true
            }
        }],
        _id: false,
        default: []
    },
    userSecrets: {
        type: [{
            userId: {
                type: SchemaTypes.String,
                required: true
            },
            secret: {
                type: SchemaTypes.String,
                required: true
            }
        }]
    }
}))