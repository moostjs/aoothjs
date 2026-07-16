import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import { TableController } from "@atscript/moost-db";

import { Document } from "../models/document.as";

@TableController(Document)
@ArbacResource("documents")
export class DocumentsController extends AsArbacDbController<typeof Document> {}
