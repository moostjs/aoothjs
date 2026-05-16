import { ArbacResource, AsArbacDbController } from "@aoothjs/arbac-moost";
import type { AtscriptDbTable } from "@atscript/db";
import { TableController } from "@atscript/moost-db";

import type { Document } from "../models/document.as";
import type { DbControllerCtor } from "./_helpers";

export function makeDocumentsController(
  table: AtscriptDbTable<typeof Document>,
): DbControllerCtor<typeof Document> {
  @TableController(table)
  @ArbacResource("documents")
  class DocumentsController extends AsArbacDbController<typeof Document> {}
  return DocumentsController as unknown as DbControllerCtor<typeof Document>;
}
