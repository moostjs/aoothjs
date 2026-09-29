import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import { Public } from "@aooth/auth-moost";
import { TableController } from "@atscript/moost-db";

import { Document } from "../models/document.as";

// Regression surface: a MISCONFIGURED `@Public()` ARBAC DB controller. `@Public()`
// skips the auth guard and the ARBAC authorize interceptor, but the controller
// resolves its scopes itself (`prepareRequest`) and fails closed — anonymous
// callers get 403 on every endpoint, never the table.
@Public()
@TableController(Document, "public-documents")
@ArbacResource("documents")
export class PublicDocumentsController extends AsArbacDbController<typeof Document> {}
