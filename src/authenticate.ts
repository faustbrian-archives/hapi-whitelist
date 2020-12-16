import { discover } from "@konceiver/remote-address";
import Boom from "@hapi/boom";
import Hapi, { AuthCredentials } from "@hapi/hapi";
import * as mm from "micromatch";
import { config } from "./config";

export const authenticate = (request: Hapi.Request, h: Hapi.ResponseToolkit) => {
	const credentials = config.get("trustHeaders")
		? discover(request, config.get("headers"))
		: request.info.remoteAddress;

	if (!credentials) {
		return h.continue;
	}

	for (const ip of config.get("whitelist")) {
		if (mm.isMatch(credentials, ip)) {
			return config.get("strategy") === "auth"
				? h.authenticated({ credentials: credentials as AuthCredentials })
				: h.continue;
		}
	}

	return Boom.unauthorized();
};
