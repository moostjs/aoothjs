import { ArbacResource, AsArbacDbController } from "@aoothjs/arbac-moost";
import type { AtscriptDbTable } from "@atscript/db";
import { TableController } from "@atscript/moost-db";

import type { Comment } from "../models/comment.as";
import type { DbControllerCtor } from "./_helpers";

export function makeCommentsController(
  table: AtscriptDbTable<typeof Comment>,
): DbControllerCtor<typeof Comment> {
  @TableController(table)
  @ArbacResource("comments")
  class CommentsController extends AsArbacDbController<typeof Comment> {}
  return CommentsController as unknown as DbControllerCtor<typeof Comment>;
}
