// Pre-built role definitions used by the codegen CLI smoke test.
// Hand-rolled (no TypeScript build step) to keep the test hermetic.

/** @type {import("@aooth/arbac-core").TArbacRole<unknown, unknown>[]} */
const roles = [
  {
    id: "editor",
    name: "Editor",
    rules: [
      { resource: "articles", action: "create" },
      { resource: "articles", action: "read" },
      { resource: "articles", action: "update" },
      { resource: "articles", action: "delete" },
      { resource: "articles", action: "list" },
      { resource: "comments", action: "moderate" },
    ],
  },
  {
    id: "viewer",
    name: "Viewer",
    rules: [
      { resource: "articles", action: "read" },
      { resource: "articles", action: "list" },
    ],
  },
];

export default roles;
