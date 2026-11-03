import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import { TableController } from "@atscript/moost-db";

import { Comment } from "../models/comment.as";

@TableController(Comment)
@ArbacResource("comments")
export class CommentsController extends AsArbacDbController<typeof Comment> {
  // `POST /comments` with `Prefer: return=representation` answers the stored
  // comment (server-generated `id`, `createdAt`, the forced tenant / author)
  // as `row` — read back under the caller's comments READ grant, exactly what
  // `GET /comments/one/:id` would answer them.
  protected returnRepresentation(): boolean {
    return true;
  }
}
