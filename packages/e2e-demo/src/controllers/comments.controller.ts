import { ArbacResource, AsArbacDbController } from "@aooth/arbac-moost";
import { TableController } from "@atscript/moost-db";

import { Comment } from "../models/comment.as";

@TableController(Comment)
@ArbacResource("comments")
export class CommentsController extends AsArbacDbController<typeof Comment> {}
