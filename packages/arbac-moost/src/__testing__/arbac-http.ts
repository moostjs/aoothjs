import { MoostHttp } from "@moostjs/event-http";
import { createProvideRegistry, createReplaceRegistry, Moost, type TClassConstructor } from "moost";

import { arbacAuthorizeInterceptor } from "../arbac.decorator";
import { MoostArbac } from "../moost-arbac";
import { type ArbacUserProvider, ArbacUserProviderToken } from "../user.provider";

/**
 * Test utility — boots a Moost HTTP app wired for ARBAC: `user` answers
 * `ArbacUserProviderToken`, `arbac` answers `MoostArbac`, and (with
 * `authorize`) `arbacAuthorizeInterceptor` runs globally. Returns the adapter
 * for `http.request(...)`. Call `clearGlobalWooks()` between boots.
 *
 * NOT exported from the package's public entry — internal use only.
 */
export async function bootArbacHttp<TUserAttrs extends object, TScope extends object>(opts: {
  arbac: MoostArbac<TUserAttrs, TScope>;
  user: ArbacUserProvider;
  controllers: Parameters<Moost["registerControllers"]>;
  authorize?: boolean;
}): Promise<MoostHttp> {
  const userClass = opts.user.constructor as TClassConstructor<ArbacUserProvider>;
  const app = new Moost();
  app.setReplaceRegistry(createReplaceRegistry([ArbacUserProviderToken, userClass]));
  app.setProvideRegistry(
    createProvideRegistry([userClass, () => opts.user], [MoostArbac, () => opts.arbac]),
  );
  if (opts.authorize) app.applyGlobalInterceptors(arbacAuthorizeInterceptor);
  const http = new MoostHttp();
  app.adapter(http);
  app.registerControllers(...opts.controllers);
  await app.init();
  return http;
}
