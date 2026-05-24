import { useArbac } from "@aooth/arbac-moost";
import { Public, useAuth } from "@aooth/auth-moost";
import type { AtscriptDbTable } from "@atscript/db";
import { useAtscriptWf } from "@atscript/moost-wf";
import { HttpError } from "@moostjs/event-http";
import {
  outletEmail,
  Step,
  StepTTL,
  useWfFinished,
  Workflow,
  WorkflowParam,
  WorkflowSchema,
} from "@moostjs/event-wf";
import { Controller } from "moost";

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

export function makeHandoverWorkflow(tables: HandoverWfTables): HandoverWorkflowCtor {
  const { projectsTable, usersTable, auditTable } = tables;

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
    async selectTarget(@WorkflowParam("context") ctx: HandoverWfCtx): Promise<unknown> {
      const wf = useAtscriptWf(HandoverTargetForm);
      const input = wf.resolveInput() as { projectId: string; targetOwner: string };

      const project = await projectsTable.findOne({
        filter: { id: input.projectId },
      });
      if (!project) {
        throw wf.requireInput({ errors: { projectId: "Project not found" } });
      }

      const currentUser = useAuth().getUserId();
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
      ctx.targetOwner = input.targetOwner;
      ctx.tenantId = project.tenantId;
      return undefined;
    }

    @Step("handoverConfirm")
    async confirm(@WorkflowParam("context") ctx: HandoverWfCtx): Promise<unknown> {
      const wf = useAtscriptWf(HandoverConfirmForm);
      const input = wf.resolveInput() as { confirm?: boolean };
      if (input.confirm !== true) {
        throw wf.requireInput({ errors: { confirm: "Must confirm to proceed" } });
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
        actor: useAuth().getUserId(),
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
