import { defineConfig, presetIcons } from "unocss";
import { asPresetVunor, allShortcuts } from "@atscript/ui-styles";
import { vunorShortcuts } from "vunor/theme";

// SSO provider brand glyphs (the `i-simple-icons:*` icons painted by
// `AsSsoProviders`). `asPresetVunor()` already registers a presetIcons for the
// baked `as` collection under the DEFAULT name `@unocss/preset-icons`; a second
// bare `presetIcons()` would be deduped away (same preset name), so this one
// gets a unique `name` and explicitly loads the installed
// `@iconify-json/simple-icons` collection. Without it every `i-simple-icons:*`
// class silently renders 0×0. Mirrors the atscript-ui `vue-demo` pattern (which
// does the same for its `i-ph:*` Phosphor glyphs). Note the COLON form
// (`i-simple-icons:google`): the collection key contains a dash, so the
// all-dash form would be ambiguous to the icon-class parser.
const brandIcons = {
  ...presetIcons({
    collections: {
      "simple-icons": () => import("@iconify-json/simple-icons/icons.json").then((m) => m.default),
    },
  }),
  name: "preset-icons-simple-icons",
};

export default defineConfig({
  presets: [...asPresetVunor(), brandIcons],
  shortcuts: [vunorShortcuts(allShortcuts)],
  // `AsSsoProviders` applies each provider's `icon` class verbatim, but those
  // strings originate server-side (the provider list is built in `app.ts` and
  // travels through workflow context), so the UnoCSS static extractor never
  // sees the token in scanned source — it must be safelisted (and the matching
  // collection installed + wired above). One line per configured provider icon.
  // See the @atscript/vue-aooth AsSsoProviders docs: "the consumer owns the
  // icon collection and UnoCSS safelist".
  safelist: ["i-simple-icons:google"],
});
