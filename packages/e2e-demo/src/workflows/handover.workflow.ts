import { ArbacPublic, useArbac } from "@aoothjs/arbac-moost";
import { Public, useAuth } from "@aoothjs/auth-moost";
import type { AtscriptDbTable } from "@atscript/db";
import { extractPassContext, serializeFormSchema } from "@atscript/moost-wf";
import type { TAtscriptAnnotatedType } from "@atscript/typescript/utils";
import { HttpError } from "@moostjs/event-http";
import {
  outletEmail,
  outletHttp,
  Step,
  StepTTL,
  useWfFinished,
  Workflow,
  WorkflowParam,
  WorkflowSchema,
} from "@moostjs/event-wf";
import { Controller, Injectable } from "moost";

import type { AuditEntry } from "../models/audit.as";
import type { Project } from "../models/project.as";
import type { DemoUser } from "../models/user.as";
import { HandoverConfirmForm, HandoverTargetForm } from "./handover.forms.as";

const HANDOVER_NOTIFY_TTL_MS = 60 * 60 * 1000;

export interface HandoverWfCtx {
  projectId?: string;
  currentOwner?: string;
  targetOwner?: string;
  tenantId?: string;
  confirmed?: boolean;
  notified?: boolean;
}

export interface HandoverWfTables {
  projectsTable: AtscriptDbTable<typeof Project>;
  usersTable: AtscriptDbTable<typeof DemoUser>;
  auditTable: AtscriptDbTable<typeof AuditEntry>;
}

export type HandoverWorkflowCtor = new (...args: never[]) => object;

/**
 * Stable encoding of handover details into the bundled `invite.magicLink`
 * email envelope's `roles` array. The auth-moost email kind enum has no slot
 * for custom workflow payloads; tests parse this back via `parseHandoverRoles`.
 */
export function encodeHandoverRoles(projectId: string, targetOwner: string): string[] {
  return [`projectId:${projectId}`, `targetOwner:${targetOwner}`];
}

export function parseHandoverRoles(roles: string[]): {
  projectId?: string;
  targetOwner?: string;
} {
  const out: { projectId?: string; targetOwner?: string } = {};
  for (const r of roles) {
    const [k, ...rest] = r.split(":");
    const v = rest.join(":");
    if (k === "projectId") out.projectId = v;
    else if (k === "targetOwner") out.targetOwner = v;
  }
  return out;
}

function reqInput(
  type: TAtscriptAnnotatedType,
  ctx: object,
  errors?: Record<string, string>,
): ReturnType<typeof outletHttp> {
  const context: Record<string, unknown> = {
    ...extractPassContext(type, ctx as Record<string, unknown>),
  };
  if (errors) context.errors = errors;
  return outletHttp(serializeFormSchema(type), context);
}

function validateForm(type: TAtscriptAnnotatedType, input: unknown): Record<string, string> | null {
  const validator = type.validator({ unknownProps: "strip" });
  try {
    validator.validate(input);
    return null;
  } catch (err) {
    if (
      err !== null &&
      typeof err === "object" &&
      "errors" in err &&
      Array.isArray((err as { errors: unknown }).errors)
    ) {
      const out: Record<string, string> = {};
      for (const e of (err as { errors: Array<{ path: string; message: string }> }).errors) {
        out[e.path || "__form"] = e.message;
      }
      return out;
    }
    throw err;
  }
}

export function makeHandoverWorkflow(tables: HandoverWfTables): HandoverWorkflowCtor {
  const { projectsTable, usersTable, auditTable } = tables;

  @ArbacPublic()
  @Injectable("FOR_EVENT")
  @Controller()
  @Public()
  class HandoverWorkflow {
    @Workflow("project.handover")
    @WorkflowSchema<HandoverWfCtx>([
      { id: "handoverSelectTarget" },
      { id: "handoverConfirm" },
      { id: "handoverNotify" },
      { id: "handoverCommit" },
    ])
    flow(): void {}

    @Step("handoverSelectTarget")
    async selectTarget(
      @WorkflowParam("input") input: { projectId?: string; targetOwner?: string } | undefined,
      @WorkflowParam("context") ctx: HandoverWfCtx,
    ): Promise<unknown> {
      if (!input) return reqInput(HandoverTargetForm, ctx);
      const errors = validateForm(HandoverTargetForm, input);
      if (errors) return reqInput(HandoverTargetForm, ctx, errors);

      const project = await projectsTable.findOne({
        filter: { id: input.projectId as string },
      });
      if (!project) {
        return reqInput(HandoverTargetForm, ctx, { projectId: "Project not found" });
      }

      const currentUser = useAuth().getCurrentUserId();
      const isOwner = project.ownerUsername === currentUser;
      if (!isOwner) {
        const { allowed } = await useArbac().evaluate({
          resource: "projects",
          action: "replace",
        });
        if (!allowed) {
          throw new HttpError(403, "Only project owner or admin can transfer ownership");
        }
      }

      ctx.projectId = project.id;
      ctx.currentOwner = project.ownerUsername;
      ctx.targetOwner = input.targetOwner as string;
      ctx.tenantId = project.tenantId;
      return undefined;
    }

    @Step("handoverConfirm")
    async confirm(
      @WorkflowParam("input") input: { confirm?: boolean } | undefined,
      @WorkflowParam("context") ctx: HandoverWfCtx,
    ): Promise<unknown> {
      if (!input) return reqInput(HandoverConfirmForm, ctx);
      const errors = validateForm(HandoverConfirmForm, input);
      if (errors) return reqInput(HandoverConfirmForm, ctx, errors);
      if (input.confirm !== true) {
        return reqInput(HandoverConfirmForm, ctx, { confirm: "Must confirm to proceed" });
      }
      ctx.confirmed = true;
      return undefined;
    }

    @Step("handoverNotify")
    @StepTTL(HANDOVER_NOTIFY_TTL_MS)
    async notify(@WorkflowParam("context") ctx: HandoverWfCtx): Promise<unknown> {
      if (ctx.notified) return undefined;
      ctx.notified = true;

      const owner = await usersTable.findOne({
        filter: { username: ctx.currentOwner as string },
      });
      if (!owner?.email) {
        // No email on record — log and short-circuit. Test fixtures seed emails.
        // biome-ignore lint/suspicious/noConsole: dev-time signal
        console.warn(`[handover] no email for owner=${ctx.currentOwner}; skipping notify`);
        return undefined;
      }
      return outletEmail(owner.email, "invite.magicLink", {
        expiresAtMs: HANDOVER_NOTIFY_TTL_MS,
        roles: encodeHandoverRoles(ctx.projectId ?? "", ctx.targetOwner ?? ""),
      });
    }

    @Step("handoverCommit")
    async commit(@WorkflowParam("context") ctx: HandoverWfCtx): Promise<void> {
      if (!ctx.projectId || !ctx.targetOwner) {
        throw new HttpError(500, "Workflow state corrupted: missing handover details");
      }
      await projectsTable.updateMany({ id: ctx.projectId }, {
        ownerUsername: ctx.targetOwner,
      } as never);
      await auditTable.insertOne({
        tenantId: ctx.tenantId ?? "",
        actor: useAuth().getCurrentUserId(),
        action: "handover",
        resource: "projects",
        recordId: ctx.projectId,
        payload: JSON.stringify({ from: ctx.currentOwner, to: ctx.targetOwner }),
      } as never);
      useWfFinished().set({
        type: "data",
        value: { ok: true, projectId: ctx.projectId, newOwner: ctx.targetOwner },
      });
    }
  }
  return HandoverWorkflow as unknown as HandoverWorkflowCtor;
}
