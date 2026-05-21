import { defineConfig } from "unocss";
import { asPresetVunor, allShortcuts } from "@atscript/ui-styles";
import { vunorShortcuts } from "vunor/theme";

export default defineConfig({
  presets: [...asPresetVunor()],
  shortcuts: [vunorShortcuts(allShortcuts)],
});
