import * as dotenv from "dotenv";
dotenv.config();

export const OWNER_PRIVATE_KEY = process.env.OWNER_PRIVATE_KEY || "";
export const NETWORK_PRIVATE_KEY = process.env.NETWORK_PRIVATE_KEY || "";
export const OPERATOR_PRIVATE_KEY = process.env.OPERATOR_PRIVATE_KEY || "";
export const RESOLVER_PRIVATE_KEY = process.env.RESOLVER_PRIVATE_KEY || "";
export const RANDOM_PRIVATE_KEY = process.env.RANDOM_PRIVATE_KEY || "";
